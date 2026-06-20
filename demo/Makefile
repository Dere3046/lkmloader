# SPDX-License-Identifier: GPL-2.0-only
obj-m := test_lkm.o

ccflags-y += -Wno-declaration-after-statement

KDIR ?= /home/Dere3046/code/cyta/kernel
PWD := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) LLVM=1 modules

clean:
	make -C $(KDIR) M=$(PWD) LLVM=1 clean
