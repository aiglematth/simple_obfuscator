#include <vector>

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

#include "CallControlFlowModule.hpp"
#include "ObfuscationModule.hpp"
#include "Obfuscator.hpp"

using namespace llvm;
using namespace std;

Obfuscator::Obfuscator(Module *M) {
    this->M = M;
    this->ObfuscationModules = {
        (ObfuscationModule *)(new CallControlFlowModule(M))
    };
}

void Obfuscator::run(void) {
    for(ObfuscationModule *OModule : this->ObfuscationModules) {
        OModule->run();
    }
}

Module *Obfuscator::get_module(void) {
    return this->M;
}

