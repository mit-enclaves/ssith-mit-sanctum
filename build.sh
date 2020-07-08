#!/bin/bash

ROOTFS_IMG=~/debian-2020-07-01a.img
## SM_DEFINES=-DENFORCE_ENCLAVE_MEASUREMENT

JOBS=8

rebuild=yes

TOP_DIR=$PWD

pushd aws-fpga
. sdk_setup.sh
sudo chmod u+s /usr/local/bin/fpga-local-cmd
popd

pushd ssith-aws-fpga;
mkdir -p build
dtc -I dts -O dtb -o build/devicetree-mit.dtb src/dts/devicetree-mit.dts
dtc -I dts -O dtb -o build/devicetree.dtb src/dts/devicetree.dts
cd build; cmake -DFPGA=1 .. && make
popd

(cd security_monitor; rm -v build/sm.*; make SM_DEFINES="${SM_DEFINES}" sm all)
#(cd linux_enclaves/build_linux/riscv-linux/; make ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- -j${JOBS} clean)
(cd linux_enclaves; make -j${JOBS} SANCTUM_QEMU=qemu SM_BUILD_DIR=../security_monitor/build build_linux)
(cd linux_enclaves; make -j${JOBS} SANCTUM_QEMU=qemu SM_BUILD_DIR=../security_monitor/build test_linux)

rm -f enclave.enc aeskey.bin
(cd pam-enclave; make)
(cd build; cmake .. && make -j${JOBS})
./build/src/encrypt-enclave ./pam-enclave/build/enclave.bin enclave.enc
riscv64-unknown-linux-gnu-objcopy -B riscv -I binary -O elf64-littleriscv ./aeskey.bin aeskey.o
riscv64-unknown-linux-gnu-ld -T ./scripts/aeskey.lds -o aeskey.elf aeskey.o
riscv64-unknown-linux-gnu-objdump -h aeskey.elf


############################################################
## update the rootfs and SM AES key
############################################################
# make -C ./build-riscv || exit
# riscv64-unknown-linux-gnu-objcopy -O binary --only-section=.text --only-section=.rodata --only-section=.data --only-section=.bss ./build-riscv/pam/pam-enclave pam-enclave.bin
make -C ./build/src -j${JOBS} || exit

make -C ./pam-enclave/ all || exit


##./build/src/encrypt-enclave pam-enclave.bin pam-enclave.enc
##./build/pam/pam-create-db

./build/src/encrypt-enclave ./pam-enclave/build/pam-enclave.bin pam-enclave.enc
./build/src/encrypt-enclave ./aes-enclave/build/aes-enclave.bin aes-enclave.enc

sudo mount -o loop ${ROOTFS_IMG} /mnt
sudo mkdir -p /mnt/ssith
sudo mkdir /mnt/lib/modules
sudo rsync -av ./pam-enclave/build/pam_enclave.so /mnt/lib/security/pam_enclave.so
sudo rsync -av ./pam-enclave/build/pam_enclave.so /mnt/lib/riscv64-linux-gnu/security/pam_enclave.so
sudo rsync -av ./pam-enclave/pam.d.testing /mnt/etc/pam.d/testing
sudo rsync -av pam-enclave.enc /mnt/ssith/pam-enclave.bin
sudo rsync -av aes-enclave.enc /mnt/ssith/aes-enclave.bin
sudo rsync -av aes-enclave/build/aes-main /mnt/ssith/aes-main
sudo umount /mnt

riscv64-unknown-linux-gnu-objcopy -B riscv -I binary -O elf64-littleriscv ./aeskey.bin aeskey.o
riscv64-unknown-linux-gnu-ld -T ./scripts/aeskey.lds -o aeskey.elf aeskey.o
riscv64-unknown-linux-gnu-objdump -h aeskey.elf

(cd ssith-aws-fpga/hw/connectal/drivers/pcieportal; make clean )
(cd ssith-aws-fpga/hw/connectal/drivers/pcieportal; make -j${JOBS} )
