# SPDX-License-Identifier: GPL-2.0-only
MODULE_NAME := lkmloader
$(MODULE_NAME)-objs := src/ksymless/ksymless.o src/loader/loader.o \
	src/loader/patch.o src/main.o
obj-m := $(MODULE_NAME).o

ccflags-y += -I$(srctree)
ccflags-y += -I$(src)/src -I$(src)/src/ksymless -I$(src)/src/loader
ccflags-y += -Wno-declaration-after-statement
ccflags-y += -Wno-unused-variable
ccflags-y += -Wno-unused-function
ccflags-y += -Wno-strict-prototypes

KDIR ?= /home/Dere3046/code/cyta/kernel
PWD := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) LLVM=1 modules

clean:
	make -C $(KDIR) M=$(PWD) LLVM=1 clean
