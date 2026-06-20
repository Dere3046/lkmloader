// SPDX-License-Identifier: GPL-2.0-only
/*
 * patch.h
 *
 * Copyright (C) 2026 dere3046
 */

#ifndef LKMLOADER_PATCH_H
#define LKMLOADER_PATCH_H

#include <linux/types.h>

int patch_module(void *buf, size_t len);

#endif
