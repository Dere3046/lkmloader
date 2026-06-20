// SPDX-License-Identifier: GPL-2.0-only
/*
 * loader.h
 *
 * Copyright (C) 2026 dere3046
 */

#ifndef LKMLOADER_LOADER_H
#define LKMLOADER_LOADER_H

#include <linux/types.h>

extern unsigned long (*kln)(const char *name);
extern char *module_path;

int lkmloader_schedule_load(void);

#endif
