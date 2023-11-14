#!/bin/bash
# AFANEH-KERNEL-BUILD menu

# Variables
menu_version="v2.3"
DIR=`readlink -f .`
OUT_DIR=$DIR/out
PARENT_DIR=`readlink -f ${DIR}/..`

export CROSS_COMPILE=$PARENT_DIR/clang-r450784e/bin/aarch64-linux-gnu-
export CC=$PARENT_DIR/clang-r450784e/bin/clang

export PLATFORM_VERSION=13
export ANDROID_MAJOR_VERSION=t
cflags+="-I${PARENT_DIR}/kernel-build-tools/linux-x86/include "
ldflags+="-Wl,-rpath,${PARENT_DIR}/kernel-build-tools/linux-x86/lib64 "
ldflags+="-L ${PARENT_DIR}/kernel-build-tools/linux-x86/lib64 "
ldflags+="-fuse-ld=lld --rtlib=compiler-rt"
export HOSTCFLAGS="$cflags"
export HOSTLDFLAGS="$ldflags"
export PLATFORM_VERSION=13
export ANDROID_MAJOR_VERSION=t
export PATH=$PARENT_DIR/clang-r450784e/bin:$PATH
export PATH=$PARENT_DIR/build-tools/path/linux-x86:$PATH
export PATH=$PARENT_DIR/kernel-build-tools/linux-x86/bin:$PATH
export TARGET_SOC=kalama
export LLVM=1 LLVM_IAS=1
export ARCH=arm64
#KERNEL_MAKE_ENV="LOCALVERSION=-afaneh92"
VARIANT=afaneh_kalama-gki

# Color
ON_BLUE=`echo -e "\033[44m"`	# On Blue
BRED=`echo -e "\033[1;31m"`	# Bold Red
BBLUE=`echo -e "\033[1;34m"`	# Bold Blue
BGREEN=`echo -e "\033[1;32m"`	# Bold Green
UNDER_LINE=`echo -e "\e[4m"`	# Text Under Line
STD=`echo -e "\033[0m"`		# Text Clear
 
clang(){
  if [ ! -d $PARENT_DIR/clang-r450784e ]; then
    echo 'clone Android Clang/LLVM Prebuilts'
    git clone --depth 1 https://gitlab.com/OhMyVenyx/clang-r450784e $PARENT_DIR/clang-r450784e
  fi
}

build_tools(){
  if [ ! -d $PARENT_DIR/build-tools ]; then
    echo 'clone prebuilt binaries of build tools'
    git clone https://android.googlesource.com/platform/prebuilts/build-tools $PARENT_DIR/build-tools
  fi
}

kernel_build_tools(){
  if [ ! -d $PARENT_DIR/kernel-build-tools ]; then
    echo 'clone prebuilt binaries of kernel build tools'
    git clone https://gitlab.com/aosp1/kernel/prebuilts/build-tools $PARENT_DIR/kernel-build-tools
  fi
}

clean(){
  echo "${BGREEN}***** Cleaning in Progress *****${STD}"
  make clean
  make mrproper
  [ -d "$OUT_DIR" ] && rm -rf $OUT_DIR
  echo "${BGREEN}***** Cleaning Done *****${STD}"
}

build_kernel(){
  echo "${BGREEN}***** Compiling kernel *****${STD}"
  [ ! -d "$OUT_DIR" ] && mkdir $OUT_DIR
  make -j$(nproc) -C $(pwd) O=$(pwd)/out $KERNEL_MAKE_ENV ${VARIANT}_defconfig
  make -j$(nproc) -C $(pwd) O=$(pwd)/out $KERNEL_MAKE_ENV

  [ -e $OUT_DIR/arch/arm64/boot/Image.gz ] && cp $OUT_DIR/arch/arm64/boot/Image.gz $OUT_DIR/Image.gz
  if [ -e $OUT_DIR/arch/arm64/boot/Image ]; then
    cp $OUT_DIR/arch/arm64/boot/Image $OUT_DIR/Image

    echo "${BGREEN}***** Ready to Roar *****${STD}"
  else
    echo 'return to Main menu' 'Kernel STUCK in BUILD!, '
  fi
}

anykernel3(){
  if [ ! -d $PARENT_DIR/AnyKernel3 ]; then
    echo 'clone AnyKernel3 - Flashable Zip Template'
    git clone https://github.com/osm0sis/AnyKernel3 $PARENT_DIR/AnyKernel3
  fi
  
  if [ -e $OUT_DIR/arch/arm64/boot/Image ]; then
    cd $PARENT_DIR/AnyKernel3
    git reset --hard
    cp $OUT_DIR/arch/arm64/boot/Image zImage
    sed -i "s/ExampleKernel by osm0sis/${VARIANT} kernel by afaneh92/g" anykernel.sh
    sed -i "s/do\.devicecheck=1/do\.devicecheck=0/g" anykernel.sh
    sed -i "s/=maguro/=/g" anykernel.sh
    sed -i "s/=toroplus/=/g" anykernel.sh
    sed -i "s/=toro/=/g" anykernel.sh
    sed -i "s/=tuna/=/g" anykernel.sh
    sed -i "s/platform\/omap\/omap_hsmmc\.0\/by-name\/boot/bootdevice\/by-name\/boot/g" anykernel.sh
    sed -i "s/backup_file/#backup_file/g" anykernel.sh
    sed -i "s/replace_string/#replace_string/g" anykernel.sh
    sed -i "s/insert_line/#insert_line/g" anykernel.sh
    sed -i "s/append_file/#append_file/g" anykernel.sh
    sed -i "s/patch_fstab/#patch_fstab/g" anykernel.sh
    sed -i "s/dump_boot/split_boot/g" anykernel.sh
    sed -i "s/write_boot/flash_boot/g" anykernel.sh
    zip -r9 $PARENT_DIR/${VARIANT}_kernel_`cat $OUT_DIR/include/config/kernel.release`_`date '+%Y_%m_%d'`.zip * -x .git README.md *placeholder
    cd $DIR
  else
    echo 'Build kernel first, '
  fi
}

clang
build_tools
kernel_build_tools
build_kernel
anykernel3
