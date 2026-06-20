// SPDX-License-Identifier: GPL-2.0-only
/*
 * loader.c — load patched .ko via kernel's internal load_module
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/elf.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/task_work.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#include <asm/syscall.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#include "kernel/module/internal.h"
#else
#include "kernel/module-internal.h"
#endif

#include "loader.h"
#include "patch.h"

unsigned long (*kln)(const char *name);

static syscall_fn_t *syscall_table;
static struct pt_regs tmp_regs;

static long __nocfi do_load(const char __user *params)
{
	int (*load_module_fn)(struct load_info *, const char __user *, int);
	ssize_t (*kernel_read_file_fn)(struct file *, loff_t, void **,
				       size_t, size_t *, enum kernel_read_file_id);
	struct file *(*filp_open_fn)(const char *, int, umode_t);
	void (*filp_close_fn)(struct file *, fl_owner_t);
	struct load_info info = {};
	struct file *f;
	void *buf = NULL;
	int len;
	long ret;

	load_module_fn = (void *)kln("load_module");
	kernel_read_file_fn = (void *)kln("kernel_read_file");
	filp_open_fn = (void *)kln("filp_open");
	filp_close_fn = (void *)kln("filp_close");

	if (!load_module_fn || !kernel_read_file_fn ||
	    !filp_open_fn || !filp_close_fn) {
		pr_err("lkmloader: missing symbols for load\n");
		return -ENOSYS;
	}

	f = filp_open_fn(module_path, O_RDONLY, 0);
	if (IS_ERR_OR_NULL(f)) {
		pr_err("lkmloader: open %s failed: %ld\n", module_path, PTR_ERR(f));
		return PTR_ERR(f);
	}

	len = kernel_read_file_fn(f, 0, &buf, INT_MAX, NULL, READING_MODULE);
	if (len < 0) {
		pr_err("lkmloader: read failed: %d\n", len);
		filp_close_fn(f, NULL);
		return len;
	}

	ret = patch_module(buf, len);
	if (ret)
		pr_warn("lkmloader: patch returned %ld\n", ret);

	info.hdr = buf;
	info.len = len;
	ret = load_module_fn(&info, params, 0);
	pr_info("lkmloader: load_module=%ld\n", ret);

	filp_close_fn(f, NULL);
	return ret;
}

static unsigned long __nocfi do_in_task_work_c(void)
{
	struct pt_regs *regs = current_pt_regs();
	char __user *params = (char __user *)(regs->sp - 1);
	unsigned long del_mod;
	long ret;

	ret = copy_to_user(params, "", 1);
	if (ret) {
		pr_err("lkmloader: copy params failed\n");
		return 0;
	}

	ret = do_load(params);
	if (ret)
		pr_err("lkmloader: load failed: %ld\n", ret);
	else
		pr_info("lkmloader: load success\n");

	del_mod = (unsigned long)syscall_table[__NR_delete_module];
	if (!del_mod) {
		pr_err("lkmloader: no delete_module\n");
		return 0;
	}

	memcpy(&tmp_regs, regs, sizeof(struct pt_regs));
	tmp_regs.regs[0] = tmp_regs.sp - sizeof("lkmloader");
	tmp_regs.regs[1] = 0;
	ret = copy_to_user((void __user *)tmp_regs.regs[0], "lkmloader",
			   sizeof("lkmloader"));
	if (ret) {
		pr_err("lkmloader: copy modname failed\n");
		return 0;
	}

	return del_mod;
}

void __naked do_in_task_work(struct callback_head *head)
{
	asm volatile(
		"stp x29, x30, [sp, #-0x10]!\n"
		"bl do_in_task_work_c\n"
		"cmp x0, #0\n"
		"b.eq 1f\n"
		"mov x17, x0\n"
		"ldr x0, =tmp_regs\n"
		"ldp x29, x30, [sp], #0x10\n"
		"br x17\n"
		"1:\n"
		"ldp x29, x30, [sp], #0x10\n"
		"ret\n"
	);
}

static struct callback_head task_work_head = {
	.func = do_in_task_work
};

int lkmloader_schedule_load(void)
{
	int (*task_work_add_fn)(struct task_struct *, struct callback_head *,
				enum task_work_notify_mode);

	task_work_add_fn = (void *)kln("task_work_add");
	if (!task_work_add_fn) {
		pr_err("lkmloader: no task_work_add\n");
		return -ENOSYS;
	}

	syscall_table = (void *)kln("sys_call_table");
	if (!syscall_table) {
		pr_err("lkmloader: no sys_call_table\n");
		return -ENOSYS;
	}

	return task_work_add_fn(current, &task_work_head, TWA_RESUME);
}
