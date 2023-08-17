#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

#include "Obfuscator.hpp"

using namespace llvm;

struct ObfuscatorPass : public ModulePass {
    static char ID;
    ObfuscatorPass() : ModulePass(ID) {}
    bool runOnModule(Module &M) override {
        Obfuscator(&M).run();
        return true;
    }
};

char ObfuscatorPass::ID = 0;

static RegisterPass<ObfuscatorPass>
    X("obfuscator", "Obfuscate the llvm bitcode",
        false,
        false
    );