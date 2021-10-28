/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2013 Regents of the University of California
 */

#include <linux/linkage.h>
#include <asm/asm.h>

#include "copy_template.S"

/* void *memcpy(void *, const void *, size_t) */
ENTRY(__memcpy)
WEAK(memcpy)
	move t6, a0  /* Preserve return value */

	.macro access op reg addr
	\op \reg, \addr
	.endm

	.macro exit
	move a0, t6
	ret
	.endm

	__copy_template

END(__memcpy)
