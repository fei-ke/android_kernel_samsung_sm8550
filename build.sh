#!/bin/bash

#
# Tested on Ubuntu 20.04
#
# 1. Install Clang/LLVM
#
# apt install -y clang llvm lld
#
# Or get Clang/LLVM from https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+archive/refs/heads/main/clang-r450784e.tar.gz 
# and add bin dir to PATH
#
# 2. Install required packages
# apt install -y git zip make xz-utils bison flex libz-dev libssl-dev libelf-dev bc cpio python3 pahole
#
# 3. Run build.sh to build kernel, do a clean before build is recommended
# make clean && rm -rf ./out
# ./build.sh <your defconfig>
# 
# 4. Image output to out/arch/arm64/boot/Image
# 

set -e

TARGET_DEFCONFIG=${1:-kalama_gki_defconfig}

cd "$(dirname "$0")"

LOCALVERSION=-android13-8

if [ "$LTO" == "thin" ]; then
  LOCALVERSION+="-thin"
fi

ARGS="
CC=clang
ARCH=arm64
LLVM=1 LLVM_IAS=1
LOCALVERSION=$LOCALVERSION
"

make -j$(nproc) -C $(pwd) O=$(pwd)/out ${ARGS} $TARGET_DEFCONFIG

if [ "$LTO" = "thin" ]; then
  ./scripts/config --file out/.config -e LTO_CLANG_THIN -d LTO_CLANG_FULL
fi

make -j$(nproc) -C $(pwd) O=$(pwd)/out ${ARGS}
