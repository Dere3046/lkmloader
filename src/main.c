// SPDX-License-Identifier: GPL-2.0-only
/*
 * main.c — lkmloader entry, ksymless-based symbol resolution
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/printk.h>
#include <linux/init.h>

#include "ksymless.h"
#include "loader.h"

char *module_path = NULL;
module_param(module_path, charp, 0644);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("dere3046");
MODULE_DESCRIPTION("LKM Loader (ksymless)");

static int __init lkmloader_init(void)
{
	unsigned long addr;
	int ret;

	pr_info("lkmloader: init\n");

	if (!module_path) {
		pr_err("lkmloader: module_path not set\n");
		return -EINVAL;
	}
	pr_info("lkmloader: target=%s\n", module_path);

	find_kallsyms_base();

	addr = kallsyms_name_to_addr("kallsyms_lookup_name");
	if (!addr) {
		pr_err("lkmloader: kallsyms_lookup_name not found\n");
		return -ENOSYS;
	}
	kln = (typeof(kln))addr;
	pr_info("lkmloader: kln=0x%lx\n", addr);

	ret = lkmloader_schedule_load();
	if (ret) {
		pr_err("lkmloader: schedule failed: %d\n", ret);
		return ret;
	}

	return 0;
}

static void __exit lkmloader_exit(void)
{
	pr_info("lkmloader: exit\n");
}

module_init(lkmloader_init);
module_exit(lkmloader_exit);
