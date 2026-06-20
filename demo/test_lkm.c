// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_lkm.c — test module loaded via lkmloader
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/init.h>
#include <linux/mm_types.h>
#include <linux/namei.h>

extern struct mm_struct init_mm;
extern int kern_path(const char *, unsigned int, struct path *);
extern unsigned long kallsyms_lookup_name(const char *name);

static int __init test_lkm_init(void)
{
	pr_info("hi kern\n");
	pr_info("test_lkm: init_mm=0x%lx\n", (unsigned long)&init_mm);
	pr_info("test_lkm: kern_path=0x%lx\n", (unsigned long)kern_path);
	pr_info("test_lkm: kallsyms_lookup_name=0x%lx\n",
		(unsigned long)kallsyms_lookup_name);
	return 0;
}

static void __exit test_lkm_exit(void)
{
	pr_info("test_lkm: exit\n");
}

module_init(test_lkm_init);
module_exit(test_lkm_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("dere3046");
MODULE_DESCRIPTION("Test LKM for lkmloader");
