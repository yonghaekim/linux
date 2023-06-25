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
    //printk("[FOR DEBUGGING] YH+ switch to aux!\n");
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
    //prev->dpt_config = csr_read(CSR_DPT_CONFIG);
    //prev->bounds_margin = csr_read(CSR_BOUNDS_MARGIN);
    prev->num_tagd = csr_read(CSR_NUM_TAGD);
    prev->num_xtag = csr_read(CSR_NUM_XTAG);
    prev->num_tagged_store = csr_read(CSR_NUM_TAGGED_STORE);
    prev->num_untagged_store = csr_read(CSR_NUM_UNTAGGED_STORE);
    prev->num_tagged_load = csr_read(CSR_NUM_TAGGED_LOAD);
    prev->num_untagged_load = csr_read(CSR_NUM_UNTAGGED_LOAD);
    prev->num_inst = csr_read(CSR_NUM_INST);
    prev->ldst_traffic = csr_read(CSR_LDST_TRAFFIC);
    prev->bounds_traffic = csr_read(CSR_BOUNDS_TRAFFIC);
    prev->num_store_hit = csr_read(CSR_NUM_STORE_HIT);
    prev->num_load_hit = csr_read(CSR_NUM_LOAD_HIT);
    prev->num_cstr = csr_read(CSR_NUM_CSTR);
    prev->num_cclr = csr_read(CSR_NUM_CCLR);
    prev->num_csrch = csr_read(CSR_NUM_CSRCH);
    //prev->num_csrch_hit = csr_read(CSR_NUM_CSRCH_HIT);
    //prev->num_cstr_itr = csr_read(CSR_NUM_CSTR_ITR);
    //prev->num_cclr_itr = csr_read(CSR_NUM_CCLR_ITR);
    //prev->num_csrch_itr = csr_read(CSR_NUM_CSRCH_ITR);
    //prev->num_chk_fail = csr_read(CSR_NUM_CHK_FAIL);
    //prev->num_cstr_fail = csr_read(CSR_NUM_CSTR_FAIL);
    //prev->num_cclr_fail = csr_read(CSR_NUM_CCLR_FAIL);
    csr_write(CSR_DPT_CONFIG, 0); // disable DPT
  }
  // if next process is traced, set cmap-related CSRs before enable tracing
  if (next->dpt_config) {
    //csr_write(CSR_BOUNDS_MARGIN, next->bounds_margin);
    csr_write(CSR_NUM_TAGD, next->num_tagd);
    csr_write(CSR_NUM_XTAG, next->num_xtag);
    csr_write(CSR_NUM_TAGGED_STORE, next->num_tagged_store);
    csr_write(CSR_NUM_UNTAGGED_STORE, next->num_untagged_store);
    csr_write(CSR_NUM_TAGGED_LOAD, next->num_tagged_load);
    csr_write(CSR_NUM_UNTAGGED_LOAD, next->num_untagged_load);
    csr_write(CSR_NUM_INST, next->num_inst);
    csr_write(CSR_LDST_TRAFFIC, next->ldst_traffic);
    csr_write(CSR_BOUNDS_TRAFFIC, next->bounds_traffic);
    csr_write(CSR_NUM_STORE_HIT, next->num_store_hit);
    csr_write(CSR_NUM_LOAD_HIT, next->num_load_hit);
    csr_write(CSR_NUM_CSTR, next->num_cstr);
    csr_write(CSR_NUM_CCLR, next->num_cclr);
    csr_write(CSR_NUM_CSRCH, next->num_csrch);
    //csr_write(CSR_NUM_CSRCH_HIT, next->num_csrch_hit);
    //csr_write(CSR_NUM_CSTR_ITR, next->num_cstr_itr);
    //csr_write(CSR_NUM_CCLR_ITR, next->num_cclr_itr);
    //csr_write(CSR_NUM_CSRCH_ITR, next->num_csrch_itr);
    //csr_write(CSR_NUM_CHK_FAIL, next->num_chk_fail);
    //csr_write(CSR_NUM_CSTR_FAIL, next->num_cstr_fail);
    //csr_write(CSR_NUM_CCLR_FAIL, next->num_cclr_fail);

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
