#ifndef HPP_CALL_CONTROL_FLOW_MODULE
#define HPP_CALL_CONTROL_FLOW_MODULE

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include "ObfuscationModule.hpp"

using namespace llvm;
using namespace std;

class CallControlFlowModule : ObfuscationModule {
    public:
        CallControlFlowModule(Module *M);
        void run(void);

    private:
        void create_main(void);
        void create_dispatcher(void);
        size_t add_dispatch(vector<Function *> ToDispatch);
        void promote_local_variables(Function &F);
        void promote_function_arguments(Function &F);
        void promote_function_return(Function &F);
        void explode(Function &F);
        void remap(Function &F);
        void clone_bb(BasicBlock *BB, Function *F);

        Function *Main;
        Function *Dispatcher;
        SwitchInst *DispatcherSW;
        vector<Function *> Dispatched;
        map<Function *, Function *> Remapped;
        vector<Instruction *> Erasable;
};

#endif