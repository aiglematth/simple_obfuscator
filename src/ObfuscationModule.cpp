#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

#include "ObfuscationModule.hpp"

using namespace llvm;

ObfuscationModule::ObfuscationModule(Module *M) {
    this->M = M;
}