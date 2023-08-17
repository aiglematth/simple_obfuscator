#ifndef HPP_OBFUSCATOR
#define HPP_OBFUSCATOR

#include <vector>

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

#include "ObfuscationModule.hpp"

using namespace llvm;
using namespace std;

class Obfuscator {
    public:
        Obfuscator(Module *M);
        void run(void);
        Module *get_module(void);

    private:
        Module *M;
        vector<ObfuscationModule *> ObfuscationModules;
};

#endif