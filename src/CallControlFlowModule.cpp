#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/DeadArgumentElimination.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include "CallControlFlowModule.hpp"
#include "ObfuscationModule.hpp"

using namespace llvm;
using namespace std;

size_t get_bitsize(uint64_t I) {
    size_t Size = 0;

    while(I != 0) {
        I >>= 1;
    }

    return Size;
}

vector<Instruction *> get_uses(Value *V, Function &F) {
    vector<Instruction *> Ret;
    for(BasicBlock &BB : F) {
        for(Instruction &I : BB) {
            for(size_t Index=0; Index<I.getNumOperands(); Index++) {
                if(I.getOperand(Index) == V) {
                    Ret.push_back(&I);
                }
            }
        }
    }
    return Ret;
}

void replace_uses(Value *AI, GlobalVariable *Ref, Function &F) {
    for(Instruction *U : get_uses(AI, F)) {
        if(Instruction *ToPatch = dyn_cast<Instruction>(U)) {
            switch(ToPatch->getOpcode()) {

                case Instruction::Load : {
                    ToPatch->setOperand(0, Ref);
                    break;
                }

                case Instruction::Store : {
                    StoreInst *StoreToPatch = dyn_cast<StoreInst>(ToPatch);
                    if(AI == StoreToPatch->getValueOperand()) {
                        ToPatch->setOperand(0, new LoadInst(Ref->getValueType(), Ref, "", StoreToPatch));
                    }
                    if(AI == StoreToPatch->getPointerOperand()) {
                        ToPatch->setOperand(1, Ref);
                    }
                    break;
                }

                default : {
                    //
                    // Possible issue...already ptr, is there any instruction dereferencing in operands ?
                    //
                    for(size_t Index=0; Index<ToPatch->getNumOperands(); Index++) {
                        if(ToPatch->getOperand(Index) == AI) {
                            ToPatch->setOperand(Index, Ref);
                        }
                    }

                    break;
                }

            }
        }
    }

}

CallControlFlowModule::CallControlFlowModule(Module *M) : ObfuscationModule(M) {}

void CallControlFlowModule::run(void) {
    vector<Function *> BaseFunctions;

    this->create_main();
    for(Function &F : this->M->functions()) {
        if(&F != this->Main && !F.isDeclaration()) {
            this->promote_local_variables(F);
            this->promote_function_arguments(F);
            this->promote_function_return(F);
            BaseFunctions.push_back(&F);
        }
    }

    for(Instruction *I : this->Erasable) {
        I->dropAllReferences();
        I->eraseFromParent();
    }
    this->Erasable.clear();

    this->create_dispatcher();
    for(Function *F : BaseFunctions) {
        this->explode(*F);
    }

    for(Instruction *I : this->Erasable) {
        I->dropAllReferences();
        I->eraseFromParent();
    }
    this->Erasable.clear();


    for(Function *F : BaseFunctions) {
        this->remap(*F);
        F->removeFromParent();
    }

    for(Instruction *I : this->Erasable) {
        I->dropAllReferences();
        I->eraseFromParent();
    }
    this->Erasable.clear();

    // for(Function &F : this->M->functions()) {
    //     errs() << F;
    // }
}

void CallControlFlowModule::create_main(void) {
    Function *OMain = this->M->getFunction("main");

    if(!OMain) {
        return;
    }

    OMain->setName("");

    ValueToValueMapTy VMap;
    this->Main = CloneFunction(OMain, VMap);
    this->Main->deleteBody();
    this->Main->setName("main");

    BasicBlock *BB = BasicBlock::Create(this->M->getContext(), "", this->Main);

    vector<Value *> MainArgs;
    for(Argument &Arg : this->Main->args()) {
        MainArgs.push_back(&Arg);
    }
    CallInst *CI = CallInst::Create(OMain->getFunctionType(), OMain, MainArgs, "", BB);
    ReturnInst::Create(this->M->getContext(), CI, BB);

    this->Dispatched.push_back(this->Main);
}

void CallControlFlowModule::create_dispatcher(void) {
    this->Dispatcher = Function::Create(
        FunctionType::get(
            Type::getVoidTy(this->M->getContext()), 
            {
                Type::getInt64Ty(this->M->getContext()), 
                Type::getInt64Ty(this->M->getContext())
            },
            false
        ),
        GlobalValue::LinkageTypes::InternalLinkage,
        "",
        *this->M
    );
    this->Dispatcher->setDSOLocal(true);

    BasicBlock *BBRet = BasicBlock::Create(this->M->getContext(), "", this->Dispatcher);
    ReturnInst::Create(this->M->getContext(), NULL, BBRet);

    BasicBlock *BBSwitch = BasicBlock::Create(this->M->getContext(), "", this->Dispatcher, BBRet);
    this->DispatcherSW = SwitchInst::Create(BinaryOperator::CreateAdd(this->Dispatcher->getArg(0), this->Dispatcher->getArg(1), "", BBSwitch), BBRet, 0, BBSwitch);
}

void CallControlFlowModule::promote_local_variables(Function &F) {
    for(BasicBlock &BB : F) {
        for(Instruction &I : BB) {
            if(AllocaInst *AI = dyn_cast<AllocaInst>(&I)) {

                GlobalVariable *Ref = new GlobalVariable(
                    *this->M,
                    AI->getAllocatedType(),
                    false, 
                    GlobalVariable::LinkageTypes::InternalLinkage, 
                    Constant::getNullValue(AI->getAllocatedType()),
                    F.getName() + "_local"
                );

                replace_uses(AI, Ref, F);

                this->Erasable.push_back(AI);

            }
        }
    }
}

void CallControlFlowModule::promote_function_arguments(Function &F) {
    vector<GlobalVariable *> FakeArgs;
    
    for(Argument &FArg : F.args()) {
        FakeArgs.push_back(new GlobalVariable(
            *this->M,
            FArg.getType(),
            false, 
            GlobalVariable::LinkageTypes::InternalLinkage, 
            Constant::getNullValue(FArg.getType()),
            F.getName() + "_arg"
        ));
        replace_uses(&FArg, FakeArgs.back(), F);
    }

    for(Function &FToPatch : this->M->functions()) {
        for(BasicBlock &BB : FToPatch) {
            for(Instruction &I : BB) {
                if(CallInst *CI = dyn_cast<CallInst>(&I)) {
                    if(CI->getCalledFunction() == &F) {
                        size_t Index = 0;
                        for(Use &ArgToReplace: CI->args()) {
                            new StoreInst(ArgToReplace.get(), FakeArgs[Index], CI);
                            Index++;
                        }
                    }
                }
            }
        }
    }

}

void CallControlFlowModule::promote_function_return(Function &F) {
    Type *ReturnType = F.getReturnType();
    if(ReturnType->isVoidTy()) {
        return;
    }

    GlobalVariable *FakeReturn = new GlobalVariable(
        *this->M,
        ReturnType,
        false, 
        GlobalVariable::LinkageTypes::InternalLinkage, 
        Constant::getNullValue(ReturnType),
        F.getName() + "_ret"
    );

    for(BasicBlock &BB : F) {
        for(Instruction &I : BB) {
            if(ReturnInst *RI = dyn_cast<ReturnInst>(&I)) {
                this->Erasable.push_back(RI);
                new StoreInst(RI->getReturnValue(), FakeReturn, RI);
                ReturnInst::Create(this->M->getContext(), NULL, RI);
            }
        }
    }

    for(Function &FToPatch : this->M->functions()) {
        for(BasicBlock &BB : FToPatch) {
            for(Instruction &I : BB) {
                if(CallInst *CI = dyn_cast<CallInst>(&I)) {
                    if(CI->getCalledFunction() == &F) {
                        CI->replaceAllUsesWith(new LoadInst(ReturnType, FakeReturn, "", CI->getNextNode()));
                    }
                }
            }
        }
    }
}

void CallControlFlowModule::explode(Function &F) {
    size_t Index = 0;

    map<BasicBlock *, Function *> BBToFn;

    for(BasicBlock &BB : F) {
        Function *BBWrapper = Function::Create(
            FunctionType::get(Type::getVoidTy(this->M->getContext()), {}, false),
            GlobalValue::LinkageTypes::InternalLinkage,
            F.getName(),
            *this->M
        );
        BBWrapper->setDSOLocal(true);
        this->Dispatched.push_back(BBWrapper);

        if(Index == 0) {
            this->Remapped[&F] = BBWrapper;
        }

        this->clone_bb(&BB, BBWrapper);

        BBToFn[&BB] = BBWrapper;

        Index++;
    }

    for(BasicBlock &BB : F) {
        BasicBlock &ToChange = BBToFn[&BB]->getEntryBlock();
        Instruction *I = &ToChange.back();

        switch(I->getOpcode()) {

            case Instruction::Br: {
                BranchInst *BR = dyn_cast<BranchInst>(I);

                vector<Function *> Successors;
                for(size_t I = 0; I < BR->getNumSuccessors(); I++) {
                    Successors.push_back(BBToFn[BR->getSuccessor(I)]);
                }
                size_t Base = this->add_dispatch(Successors);
                Value *Offset = ConstantInt::get(this->M->getContext(), APInt(64, 0));
                if(BR->isConditional()) {
                    Offset = new ZExtInst(
                        BinaryOperator::CreateNot(BR->getCondition(), "", BR), 
                        IntegerType::get(this->M->getContext(), 64), 
                        "",
                        BR
                    );
                }

                this->Erasable.push_back(I);
                CallInst::Create(
                    this->Dispatcher->getFunctionType(), 
                    this->Dispatcher, 
                    {
                        ConstantInt::get(this->M->getContext(), APInt(64, Base)),
                        Offset
                    }, 
                    "",
                    I
                );
                ReturnInst::Create(this->M->getContext(), NULL, &ToChange);


                break;
            }

            case Instruction::Switch: {
                SwitchInst *SW = dyn_cast<SwitchInst>(I);

                vector<Function *> Successors;
                for(size_t I = 0; I < SW->getNumSuccessors(); I++) {
                    Successors.push_back(BBToFn[SW->getSuccessor(I)]);
                }
                Successors.push_back(BBToFn[SW->getDefaultDest()]);
                size_t Base = this->add_dispatch(Successors);
                Value *Max  = ConstantInt::get(
                    this->M->getContext(), 
                    APInt(
                        64, 
                        (1 << get_bitsize(SW->getNumSuccessors() + 1)) - 1
                    )
                );
                Value *Offset = BinaryOperator::CreateAnd(SW->getCondition(), Max, "", I);

                this->Erasable.push_back(I);
                CallInst::Create(
                    this->Dispatcher->getFunctionType(), 
                    this->Dispatcher, 
                    {
                        ConstantInt::get(this->M->getContext(), APInt(64, Base)),
                        Offset
                    }, 
                    "",
                    I
                );
                ReturnInst::Create(this->M->getContext(), NULL, &ToChange);

                break;
            }


        }
    }
}

void CallControlFlowModule::remap(Function &F) {
    for(Function *Wrap : this->Dispatched) {
        for(BasicBlock &BB : *Wrap) {
            for(Instruction &I : BB) {
                if(CallInst *CI = dyn_cast<CallInst>(&I)) {
                    if(&F == CI->getCalledFunction()) {
                        this->Erasable.push_back(CI);
                        CallInst::Create(
                            this->Remapped[&F]->getFunctionType(),
                            this->Remapped[&F],
                            {},
                            "",
                            CI
                        );
                    }
                }
            }
        }
    }
}

size_t CallControlFlowModule::add_dispatch(vector<Function *> ToDispatch) {
    static size_t Base = 0;
    size_t SavedBase = Base;

    for(Function *F : ToDispatch) {
        ConstantInt *Offset = ConstantInt::get(this->M->getContext(), APInt(64, Base));
        BasicBlock *BBToWrapFunc = BasicBlock::Create(
            this->M->getContext(),
            "",
            this->Dispatcher
        );
        CallInst::Create(F->getFunctionType(), F, {}, "", BBToWrapFunc);
        ReturnInst::Create(this->M->getContext(), NULL, BBToWrapFunc);
        this->DispatcherSW->addCase(Offset, BBToWrapFunc);
        Base++;
    }

    return SavedBase;
}

void CallControlFlowModule::clone_bb(BasicBlock *BB, Function *F) {
    ValueToValueMapTy VMap;
    CloneBasicBlock(BB, VMap, "", F);
    
    for(auto ToTreat : VMap) {

        for(auto ToTraverse : VMap) {
            size_t Index = 0;
            for(const Use &Operand : dyn_cast<Instruction>(&*ToTraverse.first)->operands()) {
                if(Operand.get() == &*ToTreat.first) {
                    dyn_cast<Instruction>(&*ToTraverse.second)->setOperand(Index, &*ToTreat.second);
                }
                Index++;
            } 
        }

    }
}
