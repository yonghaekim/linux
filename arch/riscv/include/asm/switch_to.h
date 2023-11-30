/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#ifndef _ASM_RISCV_SWITCH_TO_H
#define _ASM_RISCV_SWITCH_TO_H

#include <linux/sched/task_stack.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/csr.h>
#include <asm/io.h> //yh+

#ifdef CONFIG_FPU
extern void __fstate_save(struct task_struct *save_to);
extern void __fstate_restore(struct task_struct *restore_from);

static inline void __fstate_clean(struct pt_regs *regs)
{
	regs->status = (regs->status & ~SR_FS) | SR_FS_CLEAN;
}

static inline void fstate_off(struct task_struct *task,
			      struct pt_regs *regs)
{
	regs->status = (regs->status & ~SR_FS) | SR_FS_OFF;
}

static inline void fstate_save(struct task_struct *task,
			       struct pt_regs *regs)
{
	if ((regs->status & SR_FS) == SR_FS_DIRTY) {
		__fstate_save(task);
		__fstate_clean(regs);
	}
}

static inline void fstate_restore(struct task_struct *task,
				  struct pt_regs *regs)
{
	if ((regs->status & SR_FS) != SR_FS_OFF) {
		__fstate_restore(task);
		__fstate_clean(regs);
	}
}

static inline void __switch_to_aux(struct task_struct *prev,
				   struct task_struct *next)
{
	struct pt_regs *regs;

	regs = task_pt_regs(prev);
	if (unlikely(regs->status & SR_SD))
		fstate_save(prev, regs);
	fstate_restore(next, task_pt_regs(next));
}

extern bool has_fpu;
#else
#define has_fpu false
#define fstate_save(task, regs) do { } while (0)
#define fstate_restore(task, regs) do { } while (0)
#define __switch_to_aux(__prev, __next) do { } while (0)
#endif

//yh+begin
/* riscv setup tracing info in context switches */
static inline __attribute__((always_inline)) void __dpt_setup(struct task_struct *prev,
          struct task_struct *next)
{
  // if previous process is traced, disable tracing and read out the entries in lbq
  if (prev->dpt_config) {
    prev->wpb_base = csr_read(CSR_WPB_BASE);
    prev->num_tagd = csr_read(CSR_NUM_TAGD);
    prev->num_xtag = csr_read(CSR_NUM_XTAG);
    prev->num_store = csr_read(CSR_NUM_STORE);
    prev->num_load = csr_read(CSR_NUM_LOAD);
    prev->num_tagged_store = csr_read(CSR_NUM_TAGGED_STORE);
    prev->num_tagged_load = csr_read(CSR_NUM_TAGGED_LOAD);
    prev->num_inst = csr_read(CSR_NUM_INST);
    prev->ldst_traffic = csr_read(CSR_LDST_TRAFFIC);
    prev->bounds_traffic = csr_read(CSR_BOUNDS_TRAFFIC);
    prev->num_store_hit = csr_read(CSR_NUM_STORE_HIT);
    prev->num_load_hit = csr_read(CSR_NUM_LOAD_HIT);
    prev->num_cstr = csr_read(CSR_NUM_CSTR);
    prev->num_cclr = csr_read(CSR_NUM_CCLR);
    prev->bnd_mask = csr_read(CSR_BND_MASK);
    prev->arena_end0 = csr_read(CSR_ARENA_END0);
    prev->arena_end1 = csr_read(CSR_ARENA_END1);
    prev->arena_end2 = csr_read(CSR_ARENA_END2);
    prev->arena_end3 = csr_read(CSR_ARENA_END3);
    prev->arena_end4 = csr_read(CSR_ARENA_END4);
    prev->arena_end5 = csr_read(CSR_ARENA_END5);
    prev->arena_end6 = csr_read(CSR_ARENA_END6);
    prev->arena_end7 = csr_read(CSR_ARENA_END7);
    prev->num_ways0 = csr_read(CSR_NUM_WAYS0);
    prev->num_ways1 = csr_read(CSR_NUM_WAYS1);
    prev->num_ways2 = csr_read(CSR_NUM_WAYS2);
    prev->num_ways3 = csr_read(CSR_NUM_WAYS3);

    csr_write(CSR_DPT_CONFIG, 0); // disable DPT
  }
  // if next process is traced, set cmap-related CSRs before enable tracing
  if (next->dpt_config) {
    csr_write(CSR_WPB_BASE, next->wpb_base);
    csr_write(CSR_NUM_TAGD, next->num_tagd);
    csr_write(CSR_NUM_XTAG, next->num_xtag);
    csr_write(CSR_NUM_STORE, next->num_store);
    csr_write(CSR_NUM_LOAD, next->num_load);
    csr_write(CSR_NUM_TAGGED_STORE, next->num_tagged_store);
    csr_write(CSR_NUM_TAGGED_LOAD, next->num_tagged_load);
    csr_write(CSR_NUM_INST, next->num_inst);
    csr_write(CSR_LDST_TRAFFIC, next->ldst_traffic);
    csr_write(CSR_BOUNDS_TRAFFIC, next->bounds_traffic);
    csr_write(CSR_NUM_STORE_HIT, next->num_store_hit);
    csr_write(CSR_NUM_LOAD_HIT, next->num_load_hit);
    csr_write(CSR_NUM_CSTR, next->num_cstr);
    csr_write(CSR_NUM_CCLR, next->num_cclr);
    csr_write(CSR_BND_MASK, next->bnd_mask);
    csr_write(CSR_ARENA_END0, next->arena_end0);
    csr_write(CSR_ARENA_END1, next->arena_end1);
    csr_write(CSR_ARENA_END2, next->arena_end2);
    csr_write(CSR_ARENA_END3, next->arena_end3);
    csr_write(CSR_ARENA_END4, next->arena_end4);
    csr_write(CSR_ARENA_END5, next->arena_end5);
    csr_write(CSR_ARENA_END6, next->arena_end6);
    csr_write(CSR_ARENA_END7, next->arena_end7);
    csr_write(CSR_NUM_WAYS0, next->num_ways0);
    csr_write(CSR_NUM_WAYS1, next->num_ways1);
    csr_write(CSR_NUM_WAYS2, next->num_ways2);
    csr_write(CSR_NUM_WAYS3, next->num_ways3);

    csr_write(CSR_DPT_CONFIG, next->dpt_config); // enable DPT
  }
}
//yh+end

extern struct task_struct *__switch_to(struct task_struct *,
				       struct task_struct *);

#define switch_to(prev, next, last)			\
do {							\
	struct task_struct *__prev = (prev);		\
	struct task_struct *__next = (next);		\
	if (has_fpu)					\
		__switch_to_aux(__prev, __next);	\
	__dpt_setup(__prev, __next); /*yh+*/ \
	((last) = __switch_to(__prev, __next));		\
} while (0)

#endif /* _ASM_RISCV_SWITCH_TO_H */
