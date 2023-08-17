ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

LLVM_DIR := /opt/llvm-16.0.4/include
INCLUDE_DIR := $(ROOT_DIR)include
BUILD_DIR := $(ROOT_DIR)build
CMAKE_OPTIONS := -DLT_LLVM_INSTALL_DIR=$(LLVM_DIR) -DINCLUDE_DIR=$(INCLUDE_DIR)

build:
	mkdir -p $(BUILD_DIR)
	cmake -B $(BUILD_DIR) $(CMAKE_OPTIONS)
	make -C $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)