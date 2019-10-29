/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2019 Regents of the University of California
 */

/*
 * Arguments:
 *	a0: dest
 *	a1: src
 *	a2: n
 *
 * The including file must define the assembler macro:
 *
 *	access insn, reg, addr
 *
 * where 'insn' is a load or store instruction mnemonic, 'reg' is the
 * register holding data, and 'addr' is the memory address.
 *
 * In addition, the macro 'exit' must be defined with the function
 * epilogue.
 *
 * The following caller-saved registers are clobbered by this routine:
 * a0-a1, a3-a7, t0-t5 (a2 and t6 are preserved)
 */

#include <asm/asm.h>

	.altmacro
	.macro __copy_template
	LOCAL _dest_aligned
	LOCAL _src_unaligned
	LOCAL _copy_head
	LOCAL _copy_block_aligned
	LOCAL _copy_block_unaligned
	LOCAL _copy_word
	LOCAL _copy_word_unaligned
	LOCAL _copy_byte
	LOCAL _copy_byte_check
	LOCAL _done_unaligned
	LOCAL _exit

	/*
	 * a3: end address of dest
	 * a4: start address of XLEN-aligned region in dest
	 * a5: end address of XLEN-aligned region in dest
	 */
	addi a4, a0, SZREG-1
	add a3, a0, a2
	andi a4, a4, ~(SZREG-1)
	andi a5, a3, ~(SZREG-1)
	bgeu a4, a5, _copy_byte_check	/* Skip word copy */

	/* Check dest alignment */
	beq a0, a4, _dest_aligned

	/* There is at least one XLEN-aligned word to copy */
	/* Copy leading bytes until dest is XLEN-aligned */
_copy_head:
	access lbu, t0, 0(a1)
	/* Schedule around 2-cycle byte load-use delay */
	addi a0, a0, 1
	addi a1, a1, 1
	access sb, t0, -1(a0)
	bltu a0, a4, _copy_head

_dest_aligned:
	/*
	 * a4: end address in XLEN-aligned region that is a multiple of
	 *     the data block size
	 */
	sub t0, a3, a0
	andi t0, t0, ~((8*SZREG)-1)
	beqz t0, _copy_word	/* Skip block copy */
	add a4, a0, t0

	/* Check src alignment */
	andi a7, a1, SZREG-1
	bnez a7, _src_unaligned

_copy_block_aligned:
	/* Handle aligned block-oriented copy */
	access REG_L, t0,       0(a1)
	access REG_L, t1,   SZREG(a1)
	access REG_L, t2, 2*SZREG(a1)
	access REG_L, t3, 3*SZREG(a1)
	access REG_L, t4, 4*SZREG(a1)
	access REG_L, t5, 5*SZREG(a1)
	access REG_L, a6, 6*SZREG(a1)
	access REG_L, a7, 7*SZREG(a1)
	addi a1, a1, 8*SZREG
	access REG_S, t0,       0(a0)
	access REG_S, t1,   SZREG(a0)
	access REG_S, t2, 2*SZREG(a0)
	access REG_S, t3, 3*SZREG(a0)
	access REG_S, t4, 4*SZREG(a0)
	access REG_S, t5, 5*SZREG(a0)
	access REG_S, a6, 6*SZREG(a0)
	access REG_S, a7, 7*SZREG(a0)
	addi a0, a0, 8*SZREG
	bltu a0, a4, _copy_block_aligned


	/* Handle word-oriented copy */
	bgeu a0, a5, _copy_byte_check
_copy_word:
	access REG_L, t0, 0(a1)
	addi a0, a0, SZREG
	addi a1, a1, SZREG
	access REG_S, t0, -SZREG(a0)
	bltu a0, a5, _copy_word

	/* Handle trailing byte-oriented copy */
	bgeu a0, a3, _exit
_copy_byte:
	access lbu, t0, 0(a1)
	/* Schedule around 2-cycle byte load-use delay */
	addi a0, a0, 1
	addi a1, a1, 1
	access sb, t0, -1(a0)
_copy_byte_check:
	bltu a0, a3, _copy_byte

_exit:
	exit

_src_unaligned:
	/* Handle unaligned block-oriented copy */
	/* a7 contains byte offset of src */
	li t1, SZREG << 3
	slli t0, a7, 3		/* Right bitshift */
	andi a1, a1, ~(SZREG-1) /* XLEN-align src pointer */
	sub t1, t1, t0		/* Left bitshift */

#define data0 t2
#define temp0 t3
#define temp1 t4
#define data1 t5
#define temp2 a5
#define temp3 a6

	access REG_L, data0, 0(a1)	/* Load first partial word */

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "Unsupported endianness"
#endif
	.macro unaligned idx
	access REG_L, data1, ((\idx+1)*SZREG)(a1)
	srl temp0, data0, t0
	sll temp1, data1, t1
	or temp0, temp0, temp1
	access REG_L, data0, ((\idx+2)*SZREG)(a1)
	access REG_S, temp0, (\idx*SZREG)(a0)
	srl temp0, data1, t0
	sll temp1, data0, t1
	or temp0, temp0, temp1
	access REG_S, temp0, ((\idx+1)*SZREG)(a0)
	.endm

_copy_block_unaligned:
	unaligned 0
	unaligned 2
	unaligned 4
	unaligned 6
	addi a0, a0, 8*SZREG
	addi a1, a1, 8*SZREG
	bltu a0, a4, _copy_block_unaligned

	bgeu a0, a5, _done_unaligned
	/* Handle unaligned word-oriented copy */
_copy_word_unaligned:
	srl temp0, data0, t0
	access REG_L, data0, SZREG(a1)
	addi a1, a1, SZREG
	sll temp1, data0, t1
	or temp0, temp0, temp1
	access REG_S, temp0, (a0)
	addi a0, a0, SZREG
	bltu a0, a5, _copy_word_unaligned

_done_unaligned:
	add a1, a1, a7	/* Re-add offset to src pointer */
	j _copy_byte_check

	.endm /* __copy_template */
