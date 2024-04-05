#!/bin/bash

#
# Tested on Ubuntu 22.04
#
# 1. Install Clang/LLVM
#
# apt install -y clang llvm lld
#
# Or get Clang/LLVM from https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+archive/refs/heads/main/clang-r450784e.tar.gz
# and add bin dir to PATH
#
# 2. Install required packages
# apt install -y git zip build-essential xz-utils bison flex libz-dev libssl-dev libelf-dev bc cpio python3 pahole
#
# 3. Run build.sh to build kernel, do a clean before build is recommended
# make clean && rm -rf ./out
# ./build.sh <your defconfig>
#
# 4. Image output to out/arch/arm64/boot/Image
# AnyKernel3 zip output to out/AnyKernel3/<your defconfig>_kernel_*.zip

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

# build kernel
make -j$(nproc) -C $(pwd) O=$(pwd)/out ${ARGS} $TARGET_DEFCONFIG

./scripts/config --file out/.config \
  -d UH \
  -d RKP \
  -d KDP \
  -d SECURITY_DEFEX \
  -d INTEGRITY \
  -d FIVE \
  -d TRIM_UNUSED_KSYMS

if [ "$LTO" = "thin" ]; then
  ./scripts/config --file out/.config -e LTO_CLANG_THIN -d LTO_CLANG_FULL
fi

make -j$(nproc) -C $(pwd) O=$(pwd)/out ${ARGS}

# pack AnyKernel3
cd out
if [ ! -d AnyKernel3 ]; then
  git clone --depth=1 https://github.com/fei-ke/AnyKernel3.git -b kalama
fi
cp arch/arm64/boot/Image AnyKernel3/zImage
name=${TARGET_DEFCONFIG%%_defconfig}_kernel_`cat include/config/kernel.release`_`date '+%Y_%m_%d'`
cd AnyKernel3
zip -r ${name}.zip * -x *.zip
echo "AnyKernel3 package output to $(realpath $name).zip"
