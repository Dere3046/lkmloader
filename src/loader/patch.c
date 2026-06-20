// SPDX-License-Identifier: GPL-2.0-only
/*
 * patch.c — ELF UND symbol patching
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/elf.h>
#include <linux/printk.h>
#include <linux/string.h>
#include "loader.h"
#include "patch.h"

int patch_module(void *buf, size_t len)
{
	Elf64_Ehdr *eh;
	Elf64_Shdr *sh, *shend;
	Elf64_Sym *symtab = NULL, *symtab_end = NULL, *s;
	char *strtab = NULL, *strtab_end = NULL;
	int idx = 0, symstr_idx = -1;

	if (len <= sizeof(Elf64_Ehdr))
		return -EINVAL;

	eh = buf;
	if (eh->e_shentsize != sizeof(Elf64_Shdr))
		return -EINVAL;
	if (eh->e_shoff + eh->e_shentsize * eh->e_shnum > len)
		return -EINVAL;

	sh = buf + eh->e_shoff;
	shend = buf + eh->e_shoff + eh->e_shentsize * eh->e_shnum;

	for (; sh < shend; sh++, idx++) {
		if (sh->sh_type == SHT_SYMTAB && !symtab) {
			if (sh->sh_entsize != sizeof(Elf64_Sym))
				continue;
			if (sh->sh_offset + sh->sh_size > len)
				continue;
			symtab = buf + sh->sh_offset;
			symtab_end = (void *)symtab + sh->sh_size;
			symstr_idx = sh->sh_link;
		} else if (sh->sh_type == SHT_STRTAB && idx == symstr_idx && !strtab) {
			if (sh->sh_offset + sh->sh_size > len)
				continue;
			strtab = buf + sh->sh_offset;
			strtab_end = strtab + sh->sh_size;
		}
	}

	if (!symtab || !strtab)
		return -EINVAL;

	for (s = symtab; s < symtab_end; s++) {
		if (s->st_shndx != SHN_UNDEF)
			continue;

		char *name = strtab + s->st_name;
		if (name >= strtab_end || name < strtab || !*name)
			continue;

		unsigned long addr = kln(name);
		if (!addr) {
			pr_warn("lkmloader: unresolved: %s\n", name);
			continue;
		}

		s->st_value = addr;
		s->st_shndx = SHN_ABS;
	}

	return 0;
}
