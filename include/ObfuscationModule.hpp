#ifndef HPP_OBFUSCATION_MODULE
#define HPP_OBFUSCATION_MODULE

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

class ObfuscationModule {
    public:
        ObfuscationModule(Module *M);
        virtual void run(void) = 0;

    protected:
        Module *M;
};

#endif