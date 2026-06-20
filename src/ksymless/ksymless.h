// SPDX-License-Identifier: GPL-2.0-only
/*
 * ksymless.h — kallsyms data discovery
 *
 * Copyright (C) 2026 dere3046
 */

#ifndef LKMLOADER_KSYMLESS_H
#define LKMLOADER_KSYMLESS_H

#include <linux/types.h>

#define MAX_FP 48
#define MAX_SCAN 128
#define MAX_ADRP 32
#define MAX_VISIT 64

struct fp_ret {
	unsigned long addr;
};

struct adrp_entry {
	unsigned long target;
	unsigned long pc;
	unsigned long b_target;
	int rd;
	int has_b;
};

/* stack helpers */
int safe_read(void *dst, const void *src, size_t sz);
unsigned long read_fp(void);
int is_ktxt(unsigned long addr);
int read_val(unsigned long addr, unsigned long *val);
int walk_stack(struct fp_ret *out, int max);
void dump_frames(struct fp_ret *frames, int n);

/* sct */
extern unsigned long sys_call_table_addr;
extern unsigned long b_target_found;
int scan_adrp_add(unsigned long base, int ninst, struct adrp_entry *out, int max);
unsigned long find_sct(struct fp_ret *frames, int nf);
void dump_sct(void);

/* kallsyms */
extern unsigned long sprint_addr;
extern unsigned long kernel_base;
extern unsigned long klbase_addr;
extern unsigned long klbase_val;
extern unsigned long kloffs_addr;
extern unsigned long klindex_addr;
extern unsigned long klseqs_addr;
extern unsigned int  klnum_val;
extern unsigned long klmarks_addr;
extern unsigned long kltable_addr;
extern unsigned long klnames_addr;
extern unsigned long klnum_addr;
extern unsigned long visited_fns[MAX_VISIT];
extern int nv;

int collect_adrp_pages(unsigned long fn, unsigned long *pages, int max);
int follow_bl(unsigned long fn, unsigned long *visited, int *nv_cnt, int depth);
void find_kallsyms_base(void);
unsigned long sym_addr(int idx);
int expand_sym(unsigned int off, char *buf, int max);
unsigned int get_sym_seq(int idx);
unsigned int get_sym_offset(unsigned int seq);
unsigned long kallsyms_name_to_addr(const char *name);
int sym_name_at(unsigned long addr, char *buf, int max);

#endif
