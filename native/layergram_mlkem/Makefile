# Copyright 2026 Layergram
# SPDX-License-Identifier: Apache-2.0

NATIVE_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
REPO_ROOT := $(abspath $(NATIVE_DIR)/../..)
BUILD_DIR ?= $(REPO_ROOT)/.dart_tool/layergram_pq/macos
UPSTREAM_DIR := $(REPO_ROOT)/third_party/mlkem-native/mlkem
UPSTREAM_TEST_DIR := $(REPO_ROOT)/third_party/mlkem-native/test
CC ?= clang
TESTING ?= 0
SANITIZE ?= 0

COMMON_FLAGS := -std=c99 -O3 -fPIC -fvisibility=hidden -Wall -Wextra \
	-Werror -Wpedantic -Wconversion -Wsign-conversion -Wshadow \
	-Wpointer-arith -Wmissing-prototypes -Wno-unused-command-line-argument \
	-I$(NATIVE_DIR) -I$(UPSTREAM_DIR) -I$(UPSTREAM_TEST_DIR) \
	-DLG_MLKEM_BUILD=1
LINK_FLAGS :=

ifeq ($(shell uname -s),Linux)
COMMON_FLAGS += -pthread
LINK_FLAGS += -pthread
endif

ifeq ($(shell uname -s),Darwin)
LINK_FLAGS += -framework Security
endif

ifeq ($(SANITIZE),1)
COMMON_FLAGS += -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined
LINK_FLAGS += -fsanitize=address,undefined
endif

ifeq ($(TESTING),1)
LIBRARY_NAME := liblayergram_mlkem_test.dylib
COMMON_FLAGS += -DLG_MLKEM_TESTING=1
else
LIBRARY_NAME := liblayergram_mlkem.dylib
endif

LIBRARY := $(BUILD_DIR)/$(LIBRARY_NAME)
ABI_TEST := $(BUILD_DIR)/layergram_mlkem_abi_test

.PHONY: all build test
.DEFAULT_GOAL := build

all: build

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(LIBRARY): layergram_mlkem.c layergram_mlkem.h \
		$(UPSTREAM_TEST_DIR)/expected_test_vectors.h | $(BUILD_DIR)
	$(CC) $(COMMON_FLAGS) -dynamiclib layergram_mlkem.c \
		$(LINK_FLAGS) -Wl,-install_name,@rpath/$(LIBRARY_NAME) -o $(LIBRARY)

build: $(LIBRARY)

$(ABI_TEST): layergram_mlkem_abi_test.c layergram_mlkem.h $(LIBRARY)
	$(CC) $(COMMON_FLAGS) layergram_mlkem_abi_test.c -L$(BUILD_DIR) \
		-llayergram_mlkem_test $(LINK_FLAGS) -Wl,-rpath,$(BUILD_DIR) \
		-o $(ABI_TEST)

test: $(ABI_TEST)
	$(ABI_TEST)
