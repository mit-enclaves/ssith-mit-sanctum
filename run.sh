#!/bin/bash

AGFI=agfi-07db500659138593b CLOCKPARAM="-a 125"

sudo modprobe portalmem
sudo rmmod pcieportal
## make -C build ;
     time fpga-load-local-image -P -S 0 -I $AGFI \
    && echo reloading preloaded image \
    && time fpga-load-local-image -S 0 -I $AGFI $CLOCKPARAM \
    && fpga-describe-local-image -S 0 \
    && sudo insmod ./ssith-aws-fpga/hw/connectal/drivers/pcieportal/pcieportal.ko \
    && ./ssith-aws-fpga/build/ssith_aws_fpga -L -G 2020 --uart-console=1 --block ${ROOTFS_IMG} --tun tap0 --xdma=0 --dma=1 --dtb ./ssith-aws-fpga/build/devicetree-mit.dtb ./linux_enclaves/build/test_linux.elf aeskey.elf
