ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

PASSES_DIR := $(ROOT_DIR)../../build/lib
BUILD_DIR := $(ROOT_DIR)build
SRC_DIR := $(ROOT_DIR)src

PASS_OBFUSCATE := $(PASSES_DIR)/libObfuscator.so

SRC_MAIN := $(SRC_DIR)/main.c
LL_MAIN := $(BUILD_DIR)/main.ll
LL_OBFUSCATED := $(BUILD_DIR)/obfuscated.ll
OBFUSCATED := $(BUILD_DIR)/obfuscated.elf
NOT_OBFUSCATED := $(BUILD_DIR)/not_obfuscated.elf

CC := clang
OPT := opt
STRIP := strip

all: build-not-obfuscated build

build: $(BUILD_DIR) $(LL_MAIN) $(LL_OBFUSCATED) $(OBFUSCATED)

build-not-obfuscated: $(BUILD_DIR) $(LL_MAIN) $(NOT_OBFUSCATED)

$(BUILD_DIR):
	mkdir $(BUILD_DIR)

$(LL_MAIN): $(SRC_MAIN)
	$(CC) -S -emit-llvm $(SRC_MAIN) -o $(LL_MAIN)

$(LL_OBFUSCATED): $(LL_MAIN)
	$(OPT) -disable-verify -S -enable-new-pm=0 -load $(PASS_OBFUSCATE) -obfuscator $(LL_MAIN) -o $(LL_OBFUSCATED)

$(OBFUSCATED): $(LL_OBFUSCATED)
	$(CC) $(LL_OBFUSCATED) -o $(OBFUSCATED)
	$(STRIP) $(OBFUSCATED)

$(NOT_OBFUSCATED): $(LL_MAIN)
	$(CC) $(LL_MAIN) -o $(NOT_OBFUSCATED)
	$(STRIP) $(NOT_OBFUSCATED)
	

clean:
	rm -rf $(BUILD_DIR)