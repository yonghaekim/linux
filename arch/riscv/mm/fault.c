// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2009 Sunplus Core Technology Co., Ltd.
 *  Lennox Wu <lennox.wu@sunplusct.com>
 *  Chen Liqin <liqin.chen@sunplusct.com>
 * Copyright (C) 2012 Regents of the University of California
 */


#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/perf_event.h>
#include <linux/signal.h>
#include <linux/uaccess.h>

#include <asm/pgalloc.h>
#include <asm/ptrace.h>
#include <asm/tlbflush.h>

#include "../kernel/head.h"
//yh+begin
#include <asm/csr.h>
#define DPT_TAG_WIDTH 16
//yh+end

/*
 * This routine handles page faults.  It determines the address and the
 * problem, and then passes it off to one of the appropriate routines.
 */
asmlinkage void do_page_fault(struct pt_regs *regs)
{
	struct task_struct *tsk;
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	unsigned long addr, cause;
	unsigned int flags = FAULT_FLAG_DEFAULT;
	int code = SEGV_MAPERR;
	vm_fault_t fault;

	cause = regs->cause;
	addr = regs->badaddr;

	tsk = current;
	mm = tsk->mm;

	/*
	 * Fault-in kernel-space virtual memory on-demand.
	 * The 'reference' page table is init_mm.pgd.
	 *
	 * NOTE! We MUST NOT take any locks for this case. We may
	 * be in an interrupt or a critical region, and should
	 * only copy the information from the master page table,
	 * nothing more.
	 */
	if (unlikely((addr >= VMALLOC_START) && (addr <= VMALLOC_END)))
		goto vmalloc_fault;

	/* Enable interrupts if they were enabled in the parent context. */
	if (likely(regs->status & SR_PIE))
		local_irq_enable();

	/*
	 * If we're in an interrupt, have no user context, or are running
	 * in an atomic region, then we must not take the fault.
	 */
	if (unlikely(faulthandler_disabled() || !mm))
		goto no_context;

	if (user_mode(regs))
		flags |= FAULT_FLAG_USER;

	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, addr);
	//yh+begin
	if (tsk->dpt_config != 0)
		tsk->num_page_faults += 1;
	//yh+end

retry:
	down_read(&mm->mmap_sem);
	vma = find_vma(mm, addr);
	if (unlikely(!vma))
		goto bad_area;
	if (likely(vma->vm_start <= addr))
		goto good_area;
	if (unlikely(!(vma->vm_flags & VM_GROWSDOWN)))
		goto bad_area;
	if (unlikely(expand_stack(vma, addr)))
		goto bad_area;

	/*
	 * Ok, we have a good vm_area for this memory access, so
	 * we can handle it.
	 */
good_area:
	code = SEGV_ACCERR;

	switch (cause) {
	case EXC_INST_PAGE_FAULT:
		if (!(vma->vm_flags & VM_EXEC))
			goto bad_area;
		break;
	case EXC_LOAD_PAGE_FAULT:
		if (!(vma->vm_flags & VM_READ))
			goto bad_area;
		break;
	case EXC_STORE_PAGE_FAULT:
		if (!(vma->vm_flags & VM_WRITE))
			goto bad_area;
		flags |= FAULT_FLAG_WRITE;
		break;
	default:
		panic("%s: unhandled cause %lu", __func__, cause);
	}

	/*
	 * If for any reason at all we could not handle the fault,
	 * make sure we exit gracefully rather than endlessly redo
	 * the fault.
	 */
	fault = handle_mm_fault(vma, addr, flags);

	/*
	 * If we need to retry but a fatal signal is pending, handle the
	 * signal first. We do not need to release the mmap_sem because it
	 * would already be released in __lock_page_or_retry in mm/filemap.c.
	 */
	if (fault_signal_pending(fault, regs))
		return;

	if (unlikely(fault & VM_FAULT_ERROR)) {
		if (fault & VM_FAULT_OOM)
			goto out_of_memory;
		else if (fault & VM_FAULT_SIGBUS)
			goto do_sigbus;
		BUG();
	}

	/*
	 * Major/minor page fault accounting is only done on the
	 * initial attempt. If we go through a retry, it is extremely
	 * likely that the page will be found in page cache at that point.
	 */
	if (flags & FAULT_FLAG_ALLOW_RETRY) {
		if (fault & VM_FAULT_MAJOR) {
			tsk->maj_flt++;
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ,
				      1, regs, addr);
		} else {
			tsk->min_flt++;
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MIN,
				      1, regs, addr);
		}
		if (fault & VM_FAULT_RETRY) {
			flags |= FAULT_FLAG_TRIED;

			/*
			 * No need to up_read(&mm->mmap_sem) as we would
			 * have already released it in __lock_page_or_retry
			 * in mm/filemap.c.
			 */
			goto retry;
		}
	}

	up_read(&mm->mmap_sem);
	return;

	/*
	 * Something tried to access memory that isn't in our memory map.
	 * Fix it, but check if it's kernel or user first.
	 */
bad_area:
	up_read(&mm->mmap_sem);
	/* User mode accesses just cause a SIGSEGV */
	if (user_mode(regs)) {
		do_trap(regs, SIGSEGV, code, addr);
		return;
	}

no_context:
	/* Are we prepared to handle this kernel fault? */
	if (fixup_exception(regs))
		return;

	/*
	 * Oops. The kernel tried to access some bad page. We'll have to
	 * terminate things with extreme prejudice.
	 */
	bust_spinlocks(1);
	pr_alert("Unable to handle kernel %s at virtual address " REG_FMT "\n",
		(addr < PAGE_SIZE) ? "NULL pointer dereference" :
		"paging request", addr);
	die(regs, "Oops");
	do_exit(SIGKILL);

	/*
	 * We ran out of memory, call the OOM killer, and return the userspace
	 * (which will retry the fault, or kill us if we got oom-killed).
	 */
out_of_memory:
	up_read(&mm->mmap_sem);
	if (!user_mode(regs))
		goto no_context;
	pagefault_out_of_memory();
	return;

do_sigbus:
	up_read(&mm->mmap_sem);
	/* Kernel mode? Handle exceptions or die */
	if (!user_mode(regs))
		goto no_context;
	do_trap(regs, SIGBUS, BUS_ADRERR, addr);
	return;

vmalloc_fault:
	{
		pgd_t *pgd, *pgd_k;
		pud_t *pud, *pud_k;
		p4d_t *p4d, *p4d_k;
		pmd_t *pmd, *pmd_k;
		pte_t *pte_k;
		int index;

		/* User mode accesses just cause a SIGSEGV */
		if (user_mode(regs))
			return do_trap(regs, SIGSEGV, code, addr);

		/*
		 * Synchronize this task's top level page-table
		 * with the 'reference' page table.
		 *
		 * Do _not_ use "tsk->active_mm->pgd" here.
		 * We might be inside an interrupt in the middle
		 * of a task switch.
		 */
		index = pgd_index(addr);
		pgd = (pgd_t *)pfn_to_virt(csr_read(CSR_SATP)) + index;
		pgd_k = init_mm.pgd + index;

		if (!pgd_present(*pgd_k))
			goto no_context;
		set_pgd(pgd, *pgd_k);

		p4d = p4d_offset(pgd, addr);
		p4d_k = p4d_offset(pgd_k, addr);
		if (!p4d_present(*p4d_k))
			goto no_context;

		pud = pud_offset(p4d, addr);
		pud_k = pud_offset(p4d_k, addr);
		if (!pud_present(*pud_k))
			goto no_context;

		/*
		 * Since the vmalloc area is global, it is unnecessary
		 * to copy individual PTEs
		 */
		pmd = pmd_offset(pud, addr);
		pmd_k = pmd_offset(pud_k, addr);
		if (!pmd_present(*pmd_k))
			goto no_context;
		set_pmd(pmd, *pmd_k);

		/*
		 * Make sure the actual PTE exists as well to
		 * catch kernel vmalloc-area accesses to non-mapped
		 * addresses. If we don't do this, this will just
		 * silently loop forever.
		 */
		pte_k = pte_offset_kernel(pmd_k, addr);
		if (!pte_present(*pte_k))
			goto no_context;

		/*
		 * The kernel assumes that TLBs don't cache invalid
		 * entries, but in RISC-V, SFENCE.VMA specifies an
		 * ordering constraint, not a cache flush; it is
		 * necessary even after writing invalid entries.
		 */
		local_flush_tlb_page(addr);

		return;
	}
}

//yh+begin
asmlinkage void do_ldchk_fault(struct pt_regs *regs)
{
  struct task_struct *tsk;
  unsigned long addr, cause;
  int code = SEGV_MAPERR;

  cause = regs->cause;
  addr = regs->badaddr;
  tsk = current;

  pr_alert("[DPT] Detected a Load Check Failure addr: 0x%lx cause: 0x%lx\n",
            addr, cause);

  long unsigned int arena_end0 = (long unsigned int) csr_read(CSR_ARENA_END0);
  long unsigned int arena_end1 = (long unsigned int) csr_read(CSR_ARENA_END1);
  long unsigned int arena_end2 = (long unsigned int) csr_read(CSR_ARENA_END2);
  long unsigned int arena_end3 = (long unsigned int) csr_read(CSR_ARENA_END3);
  long unsigned int arena_end4 = (long unsigned int) csr_read(CSR_ARENA_END4);
  long unsigned int arena_end5 = (long unsigned int) csr_read(CSR_ARENA_END5);
  long unsigned int arena_end6 = (long unsigned int) csr_read(CSR_ARENA_END6);
  long unsigned int arena_end7 = (long unsigned int) csr_read(CSR_ARENA_END7);
  long unsigned int paddr = (((long unsigned int) addr >> 23) & 0xFFFF);
  int N;

  if (paddr < ((arena_end0 >> 0) & (long unsigned int) 0xFFFF)) {
    N = 0;
  } else if (paddr < ((arena_end0 >> 16) & (long unsigned int) 0xFFFF)) {
    N = 1;
  } else if (paddr < ((arena_end0 >> 32) & (long unsigned int) 0xFFFF)) {
    N = 2;
  } else if (paddr < (arena_end0 >> 48)) {
    N = 3;
  } else if (paddr < ((arena_end1 >> 0) & (long unsigned int) 0xFFFF)) {
    N = 4;
  } else if (paddr < ((arena_end1 >> 16) & (long unsigned int) 0xFFFF)) {
    N = 5;
  } else if (paddr < ((arena_end1 >> 32) & (long unsigned int) 0xFFFF)) {
    N = 6;
  } else if (paddr < (arena_end1 >> 48)) {
    N = 7;
  } else if (paddr < ((arena_end2 >> 0) & (long unsigned int) 0xFFFF)) {
    N = 8;
  } else if (paddr < ((arena_end2 >> 16) & (long unsigned int) 0xFFFF)) {
    N = 9;
  } else if (paddr < ((arena_end2 >> 32) & (long unsigned int) 0xFFFF)) {
    N = 10;
  } else if (paddr < (arena_end2 >> 48)) {
    N = 11;
  } else if (paddr < ((arena_end3 >> 0) & (long unsigned int) 0xFFFF)) {
    N = 12;
  } else if (paddr < ((arena_end3 >> 16) & (long unsigned int) 0xFFFF)) {
    N = 13;
  } else if (paddr < ((arena_end3 >> 32) & (long unsigned int) 0xFFFF)) {
    N = 14;
  } else if (paddr < (arena_end3 >> 48)) {
    N = 15;
  } else if (paddr < ((arena_end4 >> 0) & (long unsigned int) 0xFFFF)) {
    N = 16;
  } else if (paddr < ((arena_end4 >> 16) & (long unsigned int) 0xFFFF)) {
    N = 17;
  } else if (paddr < ((arena_end4 >> 32) & (long unsigned int) 0xFFFF)) {
    N = 18;
  } else if (paddr < (arena_end4 >> 48)) {
    N = 19;
  } else if (paddr < ((arena_end5 >> 0) & (long unsigned int) 0xFFFF)) {
    N = 20;
  } else if (paddr < ((arena_end5 >> 16) & (long unsigned int) 0xFFFF)) {
    N = 21;
  } else if (paddr < ((arena_end5 >> 32) & (long unsigned int) 0xFFFF)) {
    N = 22;
  } else if (paddr < (arena_end5 >> 48)) {
    N = 23;
  } else if (paddr < ((arena_end6 >> 0) & (long unsigned int) 0xFFFF)) {
    N = 24;
  } else if (paddr < ((arena_end6 >> 16) & (long unsigned int) 0xFFFF)) {
    N = 25;
  } else if (paddr < ((arena_end6 >> 32) & (long unsigned int) 0xFFFF)) {
    N = 26;
  } else if (paddr < (arena_end6 >> 48)) {
    N = 27;
  } else if (paddr < ((arena_end7 >> 0) & (long unsigned int) 0xFFFF)) {
    N = 28;
  } else if (paddr < ((arena_end7 >> 16) & (long unsigned int) 0xFFFF)) {
    N = 29;
  } else if (paddr < ((arena_end7 >> 32) & (long unsigned int) 0xFFFF)) {
    N = 30;
  } else {
    N = 31;
  }

  pr_alert("[DPT] N: %d paddr: 0x%lx\n", N, paddr);
  pr_alert("[DPT] arena_end0: 0x%lx arena_end1: 0x%lx arena_end2: 0x%lx arena_end3: 0x%lx\n",
	    arena_end0, arena_end1, arena_end2, arena_end3);
  pr_alert("[DPT] arena_end4: 0x%lx arena_end5: 0x%lx arena_end6: 0x%lx arena_end7: 0x%lx\n",
	    arena_end4, arena_end5, arena_end6, arena_end7);

  long unsigned int num_ways0 = (long unsigned int) csr_read(CSR_NUM_WAYS0);
  long unsigned int num_ways1 = (long unsigned int) csr_read(CSR_NUM_WAYS1);
  long unsigned int num_ways2 = (long unsigned int) csr_read(CSR_NUM_WAYS2);
  long unsigned int num_ways3 = (long unsigned int) csr_read(CSR_NUM_WAYS3);

  pr_alert("[DPT] num_ways0: 0x%lx num_ways1: 0x%lx num_ways2: 0x%lx num_ways3: 0x%lx\n",
            num_ways0, num_ways1, num_ways2, num_ways3); 

  long unsigned int dpt_config = (long unsigned int) csr_read(CSR_DPT_CONFIG);
  pr_alert("[DPT] dpt_config: 0x%lx\n", dpt_config);

  do_trap(regs, SIGSEGV, code, addr);
  return;
}

asmlinkage void do_stchk_fault(struct pt_regs *regs)
{
  struct task_struct *tsk;
  unsigned long addr, cause;
  int code = SEGV_MAPERR;

  cause = regs->cause;
  addr = regs->badaddr;
  tsk = current;

  pr_alert("[DPT] Detected a Store Check Failure addr: 0x%lx cause: 0x%lx\n",
            addr, cause);

  long unsigned int arena_end0 = (long unsigned int) csr_read(CSR_ARENA_END0);
  long unsigned int arena_end1 = (long unsigned int) csr_read(CSR_ARENA_END1);
  long unsigned int arena_end2 = (long unsigned int) csr_read(CSR_ARENA_END2);
  long unsigned int arena_end3 = (long unsigned int) csr_read(CSR_ARENA_END3);
  long unsigned int arena_end4 = (long unsigned int) csr_read(CSR_ARENA_END4);
  long unsigned int arena_end5 = (long unsigned int) csr_read(CSR_ARENA_END5);
  long unsigned int arena_end6 = (long unsigned int) csr_read(CSR_ARENA_END6);
  long unsigned int arena_end7 = (long unsigned int) csr_read(CSR_ARENA_END7);
  pr_alert("[DPT] arena_end0: 0x%lx arena_end1: 0x%lx arena_end2: 0x%lx arena_end3: 0x%lx\n",
	    arena_end0, arena_end1, arena_end2, arena_end3);
  pr_alert("[DPT] arena_end4: 0x%lx arena_end5: 0x%lx arena_end6: 0x%lx arena_end7: 0x%lx\n",
	    arena_end4, arena_end5, arena_end6, arena_end7);

  do_trap(regs, SIGSEGV, code, addr);
  return;
}

asmlinkage void do_cstr_fault(struct pt_regs *regs)
{
  struct task_struct *tsk;
  unsigned long addr, cause;

  cause = regs->cause;
  addr = regs->badaddr;
  tsk = current;

  //long unsigned int config = tsk->dpt_config;
  long unsigned int dpt_config = (long unsigned int) csr_read(CSR_DPT_CONFIG);
  int N;
  long unsigned int num_ways;
  long unsigned int mode = ((dpt_config >> 57) & 0x3);
 
  if (mode != 1) { 
    N = 0;
  } else {
    long unsigned int arena_end0 = (long unsigned int) csr_read(CSR_ARENA_END0);
    long unsigned int arena_end1 = (long unsigned int) csr_read(CSR_ARENA_END1);
    long unsigned int arena_end2 = (long unsigned int) csr_read(CSR_ARENA_END2);
    long unsigned int arena_end3 = (long unsigned int) csr_read(CSR_ARENA_END3);
    long unsigned int arena_end4 = (long unsigned int) csr_read(CSR_ARENA_END4);
    long unsigned int arena_end5 = (long unsigned int) csr_read(CSR_ARENA_END5);
    long unsigned int arena_end6 = (long unsigned int) csr_read(CSR_ARENA_END6);
    long unsigned int arena_end7 = (long unsigned int) csr_read(CSR_ARENA_END7);
    long unsigned int paddr = (((long unsigned int) addr >> 23) & 0xFFFF);

    if (paddr < ((arena_end0 >> 0) & (long unsigned int) 0xFFFF)) {
      N = 0;
    } else if (paddr < ((arena_end0 >> 16) & (long unsigned int) 0xFFFF)) {
      N = 1;
    } else if (paddr < ((arena_end0 >> 32) & (long unsigned int) 0xFFFF)) {
      N = 2;
    } else if (paddr < (arena_end0 >> 48)) {
      N = 3;
    } else if (paddr < ((arena_end1 >> 0) & (long unsigned int) 0xFFFF)) {
      N = 4;
    } else if (paddr < ((arena_end1 >> 16) & (long unsigned int) 0xFFFF)) {
      N = 5;
    } else if (paddr < ((arena_end1 >> 32) & (long unsigned int) 0xFFFF)) {
      N = 6;
    } else if (paddr < (arena_end1 >> 48)) {
      N = 7;
    } else if (paddr < ((arena_end2 >> 0) & (long unsigned int) 0xFFFF)) {
      N = 8;
    } else if (paddr < ((arena_end2 >> 16) & (long unsigned int) 0xFFFF)) {
      N = 9;
    } else if (paddr < ((arena_end2 >> 32) & (long unsigned int) 0xFFFF)) {
      N = 10;
    } else if (paddr < (arena_end2 >> 48)) {
      N = 11;
    } else if (paddr < ((arena_end3 >> 0) & (long unsigned int) 0xFFFF)) {
      N = 12;
    } else if (paddr < ((arena_end3 >> 16) & (long unsigned int) 0xFFFF)) {
      N = 13;
    } else if (paddr < ((arena_end3 >> 32) & (long unsigned int) 0xFFFF)) {
      N = 14;
    } else if (paddr < (arena_end3 >> 48)) {
      N = 15;
    } else if (paddr < ((arena_end4 >> 0) & (long unsigned int) 0xFFFF)) {
      N = 16;
    } else if (paddr < ((arena_end4 >> 16) & (long unsigned int) 0xFFFF)) {
      N = 17;
    } else if (paddr < ((arena_end4 >> 32) & (long unsigned int) 0xFFFF)) {
      N = 18;
    } else if (paddr < (arena_end4 >> 48)) {
      N = 19;
    } else if (paddr < ((arena_end5 >> 0) & (long unsigned int) 0xFFFF)) {
      N = 20;
    } else if (paddr < ((arena_end5 >> 16) & (long unsigned int) 0xFFFF)) {
      N = 21;
    } else if (paddr < ((arena_end5 >> 32) & (long unsigned int) 0xFFFF)) {
      N = 22;
    } else if (paddr < (arena_end5 >> 48)) {
      N = 23;
    } else if (paddr < ((arena_end6 >> 0) & (long unsigned int) 0xFFFF)) {
      N = 24;
    } else if (paddr < ((arena_end6 >> 16) & (long unsigned int) 0xFFFF)) {
      N = 25;
    } else if (paddr < ((arena_end6 >> 32) & (long unsigned int) 0xFFFF)) {
      N = 26;
    } else if (paddr < (arena_end6 >> 48)) {
      N = 27;
    } else if (paddr < ((arena_end7 >> 0) & (long unsigned int) 0xFFFF)) {
      N = 28;
    } else if (paddr < ((arena_end7 >> 16) & (long unsigned int) 0xFFFF)) {
      N = 29;
    } else if (paddr < ((arena_end7 >> 32) & (long unsigned int) 0xFFFF)) {
      N = 30;
    } else {
      N = 31;
    }
  }
//  pr_alert("[DPT] N: %d paddr: 0x%lx\n", N, paddr);
//  pr_alert("[DPT] arena_end0: 0x%lx arena_end1: 0x%lx arena_end2: 0x%lx arena_end3: 0x%lx\n",
//	    arena_end0, arena_end1, arena_end2, arena_end3);
//  pr_alert("[DPT] arena_end4: 0x%lx arena_end5: 0x%lx arena_end6: 0x%lx arena_end7: 0x%lx\n",
//	    arena_end4, arena_end5, arena_end6, arena_end7);

  if (mode == 1) {
    if (N == 0) {
      long unsigned int csr_num_ways0 = (long unsigned int) csr_read(CSR_NUM_WAYS0);
      num_ways = ((csr_num_ways0 >> 0) & (long unsigned int) 0xFFFF);
      csr_num_ways0 = ((csr_num_ways0 & ~((long unsigned int) 0xFFFF)) | ((num_ways << 1) << 0));
      csr_write(CSR_NUM_WAYS0, csr_num_ways0);
      current->num_ways0 = csr_num_ways0;
    } else if (N == 1) {
      long unsigned int csr_num_ways0 = (long unsigned int) csr_read(CSR_NUM_WAYS0);
      num_ways = ((csr_num_ways0 >> 16) & (long unsigned int) 0xFFFF);
      csr_num_ways0 = ((csr_num_ways0 & ~((long unsigned int) 0xFFFF0000)) | ((num_ways << 1) << 16));
      csr_write(CSR_NUM_WAYS0, csr_num_ways0);
      current->num_ways0 = csr_num_ways0;
    } else if (N == 2) {
      long unsigned int csr_num_ways0 = (long unsigned int) csr_read(CSR_NUM_WAYS0);
      num_ways = ((csr_num_ways0 >> 32) & (long unsigned int) 0xFFFF);
      csr_num_ways0 = ((csr_num_ways0 & ~((long unsigned int) 0xFFFF00000000)) | ((num_ways << 1) << 32));
      csr_write(CSR_NUM_WAYS0, csr_num_ways0);
      current->num_ways0 = csr_num_ways0;
    } else if (N == 3) {
      long unsigned int csr_num_ways0 = (long unsigned int) csr_read(CSR_NUM_WAYS0);
      num_ways = ((csr_num_ways0 >> 48) & (long unsigned int) 0xFFFF);
      csr_num_ways0 = ((csr_num_ways0 & ~((long unsigned int) 0xFFFF000000000000)) | ((num_ways << 1) << 48));
      csr_write(CSR_NUM_WAYS0, csr_num_ways0);
      current->num_ways0 = csr_num_ways0;
    } else if (N == 4) {
      long unsigned int csr_num_ways1 = (long unsigned int) csr_read(CSR_NUM_WAYS1);
      num_ways = ((csr_num_ways1 >> 0) & (long unsigned int) 0xFFFF);
      csr_num_ways1 = ((csr_num_ways1 & ~((long unsigned int) 0xFFFF)) | ((num_ways << 1) << 0));
      csr_write(CSR_NUM_WAYS1, csr_num_ways1);
      current->num_ways1 = csr_num_ways1;
    } else if (N == 5) {
      long unsigned int csr_num_ways1 = (long unsigned int) csr_read(CSR_NUM_WAYS1);
      num_ways = ((csr_num_ways1 >> 16) & (long unsigned int) 0xFFFF);
      csr_num_ways1 = ((csr_num_ways1 & ~((long unsigned int) 0xFFFF0000)) | ((num_ways << 1) << 16));
      csr_write(CSR_NUM_WAYS1, csr_num_ways1);
      current->num_ways1 = csr_num_ways1;
    } else if (N == 6) {
      long unsigned int csr_num_ways1 = (long unsigned int) csr_read(CSR_NUM_WAYS1);
      num_ways = ((csr_num_ways1 >> 32) & (long unsigned int) 0xFFFF);
      csr_num_ways1 = ((csr_num_ways1 & ~((long unsigned int) 0xFFFF00000000)) | ((num_ways << 1) << 32));
      csr_write(CSR_NUM_WAYS1, csr_num_ways1);
      current->num_ways1 = csr_num_ways1;
    } else if (N == 7) {
      long unsigned int csr_num_ways1 = (long unsigned int) csr_read(CSR_NUM_WAYS1);
      num_ways = ((csr_num_ways1 >> 48) & (long unsigned int) 0xFFFF);
      csr_num_ways1 = ((csr_num_ways1 & ~((long unsigned int) 0xFFFF000000000000)) | ((num_ways << 1) << 48));
      csr_write(CSR_NUM_WAYS1, csr_num_ways1);
      current->num_ways1 = csr_num_ways1;
    } else if (N == 8) {
      long unsigned int csr_num_ways2 = (long unsigned int) csr_read(CSR_NUM_WAYS2);
      num_ways = ((csr_num_ways2 >> 0) & (long unsigned int) 0xFFFF);
      csr_num_ways2 = ((csr_num_ways2 & ~((long unsigned int) 0xFFFF)) | ((num_ways << 1) << 0));
      csr_write(CSR_NUM_WAYS2, csr_num_ways2);
      current->num_ways2 = csr_num_ways2;
    } else if (N == 9) {
      long unsigned int csr_num_ways2 = (long unsigned int) csr_read(CSR_NUM_WAYS2);
      num_ways = ((csr_num_ways2 >> 16) & (long unsigned int) 0xFFFF);
      csr_num_ways2 = ((csr_num_ways2 & ~((long unsigned int) 0xFFFF0000)) | ((num_ways << 1) << 16));
      csr_write(CSR_NUM_WAYS2, csr_num_ways2);
      current->num_ways2 = csr_num_ways2;
    } else if (N == 10) {
      long unsigned int csr_num_ways2 = (long unsigned int) csr_read(CSR_NUM_WAYS2);
      num_ways = ((csr_num_ways2 >> 32) & (long unsigned int) 0xFFFF);
      csr_num_ways2 = ((csr_num_ways2 & ~((long unsigned int) 0xFFFF00000000)) | ((num_ways << 1) << 32));
      csr_write(CSR_NUM_WAYS2, csr_num_ways2);
      current->num_ways2 = csr_num_ways2;
    } else if (N == 11) {
      long unsigned int csr_num_ways2 = (long unsigned int) csr_read(CSR_NUM_WAYS2);
      num_ways = ((csr_num_ways2 >> 48) & (long unsigned int) 0xFFFF);
      csr_num_ways2 = ((csr_num_ways2 & ~((long unsigned int) 0xFFFF000000000000)) | ((num_ways << 1) << 48));
      csr_write(CSR_NUM_WAYS2, csr_num_ways2);
      current->num_ways2 = csr_num_ways2;
    } else if (N == 12) {
      long unsigned int csr_num_ways3 = (long unsigned int) csr_read(CSR_NUM_WAYS3);
      num_ways = ((csr_num_ways3 >> 0) & (long unsigned int) 0xFFFF);
      csr_num_ways3 = ((csr_num_ways3 & ~((long unsigned int) 0xFFFF)) | ((num_ways << 1) << 0));
      csr_write(CSR_NUM_WAYS3, csr_num_ways3);
      current->num_ways3 = csr_num_ways3;
    } else if (N == 13) {
      long unsigned int csr_num_ways3 = (long unsigned int) csr_read(CSR_NUM_WAYS3);
      num_ways = ((csr_num_ways3 >> 16) & (long unsigned int) 0xFFFF);
      csr_num_ways3 = ((csr_num_ways3 & ~((long unsigned int) 0xFFFF0000)) | ((num_ways << 1) << 16));
      csr_write(CSR_NUM_WAYS3, csr_num_ways3);
      current->num_ways3 = csr_num_ways3;
    } else if (N == 14) {
      long unsigned int csr_num_ways3 = (long unsigned int) csr_read(CSR_NUM_WAYS3);
      num_ways = ((csr_num_ways3 >> 32) & (long unsigned int) 0xFFFF);
      csr_num_ways3 = ((csr_num_ways3 & ~((long unsigned int) 0xFFFF00000000)) | ((num_ways << 1) << 32));
      csr_write(CSR_NUM_WAYS3, csr_num_ways3);
      current->num_ways3 = csr_num_ways3;
    } else if (N == 15) {
      long unsigned int csr_num_ways3 = (long unsigned int) csr_read(CSR_NUM_WAYS3);
      num_ways = ((csr_num_ways3 >> 48) & (long unsigned int) 0xFFFF);
      csr_num_ways3 = ((csr_num_ways3 & ~((long unsigned int) 0xFFFF000000000000)) | ((num_ways << 1) << 48));
      csr_write(CSR_NUM_WAYS3, csr_num_ways3);
      current->num_ways3 = csr_num_ways3;
    } else if (N == 16) {
      long unsigned int csr_num_ways4 = (long unsigned int) csr_read(CSR_NUM_WAYS4);
      num_ways = ((csr_num_ways4 >> 0) & (long unsigned int) 0xFFFF);
      csr_num_ways4 = ((csr_num_ways4 & ~((long unsigned int) 0xFFFF)) | ((num_ways << 1) << 0));
      csr_write(CSR_NUM_WAYS4, csr_num_ways4);
      current->num_ways4 = csr_num_ways4;
    } else if (N == 17) {
      long unsigned int csr_num_ways4 = (long unsigned int) csr_read(CSR_NUM_WAYS4);
      num_ways = ((csr_num_ways4 >> 16) & (long unsigned int) 0xFFFF);
      csr_num_ways4 = ((csr_num_ways4 & ~((long unsigned int) 0xFFFF0000)) | ((num_ways << 1) << 16));
      csr_write(CSR_NUM_WAYS4, csr_num_ways4);
      current->num_ways4 = csr_num_ways4;
    } else if (N == 18) {
      long unsigned int csr_num_ways4 = (long unsigned int) csr_read(CSR_NUM_WAYS4);
      num_ways = ((csr_num_ways4 >> 32) & (long unsigned int) 0xFFFF);
      csr_num_ways4 = ((csr_num_ways4 & ~((long unsigned int) 0xFFFF00000000)) | ((num_ways << 1) << 32));
      csr_write(CSR_NUM_WAYS4, csr_num_ways4);
      current->num_ways4 = csr_num_ways4;
    } else if (N == 19) {
      long unsigned int csr_num_ways4 = (long unsigned int) csr_read(CSR_NUM_WAYS4);
      num_ways = ((csr_num_ways4 >> 48) & (long unsigned int) 0xFFFF);
      csr_num_ways4 = ((csr_num_ways4 & ~((long unsigned int) 0xFFFF000000000000)) | ((num_ways << 1) << 48));
      csr_write(CSR_NUM_WAYS4, csr_num_ways4);
      current->num_ways4 = csr_num_ways4;
    } else if (N == 20) {
      long unsigned int csr_num_ways5 = (long unsigned int) csr_read(CSR_NUM_WAYS5);
      num_ways = ((csr_num_ways5 >> 0) & (long unsigned int) 0xFFFF);
      csr_num_ways5 = ((csr_num_ways5 & ~((long unsigned int) 0xFFFF)) | ((num_ways << 1) << 0));
      csr_write(CSR_NUM_WAYS5, csr_num_ways5);
      current->num_ways5 = csr_num_ways5;
    } else if (N == 21) {
      long unsigned int csr_num_ways5 = (long unsigned int) csr_read(CSR_NUM_WAYS5);
      num_ways = ((csr_num_ways5 >> 16) & (long unsigned int) 0xFFFF);
      csr_num_ways5 = ((csr_num_ways5 & ~((long unsigned int) 0xFFFF0000)) | ((num_ways << 1) << 16));
      csr_write(CSR_NUM_WAYS5, csr_num_ways5);
      current->num_ways5 = csr_num_ways5;
    } else if (N == 22) {
      long unsigned int csr_num_ways5 = (long unsigned int) csr_read(CSR_NUM_WAYS5);
      num_ways = ((csr_num_ways5 >> 32) & (long unsigned int) 0xFFFF);
      csr_num_ways5 = ((csr_num_ways5 & ~((long unsigned int) 0xFFFF00000000)) | ((num_ways << 1) << 32));
      csr_write(CSR_NUM_WAYS5, csr_num_ways5);
      current->num_ways5 = csr_num_ways5;
    } else if (N == 23) {
      long unsigned int csr_num_ways5 = (long unsigned int) csr_read(CSR_NUM_WAYS5);
      num_ways = ((csr_num_ways5 >> 48) & (long unsigned int) 0xFFFF);
      csr_num_ways5 = ((csr_num_ways5 & ~((long unsigned int) 0xFFFF000000000000)) | ((num_ways << 1) << 48));
      csr_write(CSR_NUM_WAYS5, csr_num_ways5);
      current->num_ways5 = csr_num_ways5;
    } else if (N == 24) {
      long unsigned int csr_num_ways6 = (long unsigned int) csr_read(CSR_NUM_WAYS6);
      num_ways = ((csr_num_ways6 >> 0) & (long unsigned int) 0xFFFF);
      csr_num_ways6 = ((csr_num_ways6 & ~((long unsigned int) 0xFFFF)) | ((num_ways << 1) << 0));
      csr_write(CSR_NUM_WAYS6, csr_num_ways6);
      current->num_ways6 = csr_num_ways6;
    } else if (N == 25) {
      long unsigned int csr_num_ways6 = (long unsigned int) csr_read(CSR_NUM_WAYS6);
      num_ways = ((csr_num_ways6 >> 16) & (long unsigned int) 0xFFFF);
      csr_num_ways6 = ((csr_num_ways6 & ~((long unsigned int) 0xFFFF0000)) | ((num_ways << 1) << 16));
      csr_write(CSR_NUM_WAYS6, csr_num_ways6);
      current->num_ways6 = csr_num_ways6;
    } else if (N == 26) {
      long unsigned int csr_num_ways6 = (long unsigned int) csr_read(CSR_NUM_WAYS6);
      num_ways = ((csr_num_ways6 >> 32) & (long unsigned int) 0xFFFF);
      csr_num_ways6 = ((csr_num_ways6 & ~((long unsigned int) 0xFFFF00000000)) | ((num_ways << 1) << 32));
      csr_write(CSR_NUM_WAYS6, csr_num_ways6);
      current->num_ways6 = csr_num_ways6;
    } else if (N == 27) {
      long unsigned int csr_num_ways6 = (long unsigned int) csr_read(CSR_NUM_WAYS6);
      num_ways = ((csr_num_ways6 >> 48) & (long unsigned int) 0xFFFF);
      csr_num_ways6 = ((csr_num_ways6 & ~((long unsigned int) 0xFFFF000000000000)) | ((num_ways << 1) << 48));
      csr_write(CSR_NUM_WAYS6, csr_num_ways6);
      current->num_ways6 = csr_num_ways6;
    } else if (N == 28) {
      long unsigned int csr_num_ways7 = (long unsigned int) csr_read(CSR_NUM_WAYS7);
      num_ways = ((csr_num_ways7 >> 0) & (long unsigned int) 0xFFFF);
      csr_num_ways7 = ((csr_num_ways7 & ~((long unsigned int) 0xFFFF)) | ((num_ways << 1) << 0));
      csr_write(CSR_NUM_WAYS7, csr_num_ways7);
      current->num_ways7 = csr_num_ways7;
    } else if (N == 29) {
      long unsigned int csr_num_ways7 = (long unsigned int) csr_read(CSR_NUM_WAYS7);
      num_ways = ((csr_num_ways7 >> 16) & (long unsigned int) 0xFFFF);
      csr_num_ways7 = ((csr_num_ways7 & ~((long unsigned int) 0xFFFF0000)) | ((num_ways << 1) << 16));
      csr_write(CSR_NUM_WAYS7, csr_num_ways7);
      current->num_ways7 = csr_num_ways7;
    } else if (N == 30) {
      long unsigned int csr_num_ways7 = (long unsigned int) csr_read(CSR_NUM_WAYS7);
      num_ways = ((csr_num_ways7 >> 32) & (long unsigned int) 0xFFFF);
      csr_num_ways7 = ((csr_num_ways7 & ~((long unsigned int) 0xFFFF00000000)) | ((num_ways << 1) << 32));
      csr_write(CSR_NUM_WAYS7, csr_num_ways7);
      current->num_ways7 = csr_num_ways7;
    } else {
      long unsigned int csr_num_ways7 = (long unsigned int) csr_read(CSR_NUM_WAYS7);
      num_ways = ((csr_num_ways7 >> 48) & (long unsigned int) 0xFFFF);
      csr_num_ways7 = ((csr_num_ways7 & ~((long unsigned int) 0xFFFF000000000000)) | ((num_ways << 1) << 48));
      csr_write(CSR_NUM_WAYS7, csr_num_ways7);
      current->num_ways7 = csr_num_ways7;
    }

    pr_alert("[DPT] Resize CMT[%d]! addr: 0x%lx num_ways: (0x%lx->0x%lx)\n",
              N, addr, num_ways, (num_ways << 1));
  } else if (mode == 0) { // mode 0
    long unsigned int csr_num_ways0 = (long unsigned int) csr_read(CSR_NUM_WAYS0);
    num_ways = ((csr_num_ways0 >> 0) & (long unsigned int) 0xFFFF);
    if (num_ways < 8) {
      csr_num_ways0 = ((csr_num_ways0 & ~((long unsigned int) 0xFFFF)) | ((num_ways << 1) << 0));
      pr_alert("[DPT] Resize CMT[%d]! addr: 0x%lx num_ways: (0x%lx->0x%lx)\n",
                N, addr, num_ways, (num_ways << 1));
    } else {
      csr_num_ways0 = ((csr_num_ways0 & ~((long unsigned int) 0xFFFF)) | ((num_ways + 8) << 0));
      pr_alert("[DPT] Resize CMT[%d]! addr: 0x%lx num_ways: (0x%lx->0x%lx)\n",
                N, addr, num_ways, (num_ways + 8));
    }
    csr_write(CSR_NUM_WAYS0, csr_num_ways0);
    current->num_ways0 = csr_num_ways0;
  } else { // mode 2
    long unsigned int csr_num_ways0 = (long unsigned int) csr_read(CSR_NUM_WAYS0);
    num_ways = ((csr_num_ways0 >> 0) & (long unsigned int) 0xFFFF);
    csr_num_ways0 = ((csr_num_ways0 & ~((long unsigned int) 0xFFFF)) | ((num_ways << 1) << 0));
    csr_write(CSR_NUM_WAYS0, csr_num_ways0);
    current->num_ways0 = csr_num_ways0;
    pr_alert("[DPT] Resize CMT[%d]! addr: 0x%lx num_ways: (0x%lx->0x%lx)\n",
              N, addr, num_ways, (num_ways << 1));
  }

  //long unsigned threshold = (((dpt_config >> 56) & 0x1) == 0) ? 4 : 8;

  if (mode != 2 && (num_ways % 8) == 0) { // NUM_WAYS_THRES = 4 * 2
  //if (num_ways == threshold) { // NUM_WAYS_THRES = 4 * 2
    dpt_config = (dpt_config | ((long unsigned int) 0x1 << 54));
    csr_write(CSR_DPT_CONFIG, dpt_config);
    current->dpt_config = dpt_config;
    //pr_alert("[DPT] Set ALLOC_NEW_ARENA dpt_config: 0x%lx\n", dpt_config);
  }

  //pr_alert("[DPT] Resize CMT[%d]! config: 0x%lx num_ways: (0x%lx->0x%lx) addr: 0x%lx cause: 0x%lx\n",
  //          N, dpt_config, num_ways, num_ways*2, addr, cause);

  return;
}

asmlinkage void do_cclr_fault(struct pt_regs *regs)
{
  struct task_struct *tsk;
  unsigned long addr, cause;
  int code = SEGV_MAPERR;

  cause = regs->cause;
  addr = regs->badaddr;
  tsk = current;

  pr_alert("[DPT] Detected a CCLR Failure addr: 0x%lx cause: 0x%lx\n",
            addr, cause);

  do_trap(regs, SIGSEGV, code, addr);
  return;
}

/*
 * This routine handles bounds table resizing.
    It determines the address and the
 * problem, and then passes it off to one of the appropriate routines.
 */
//asmlinkage void do_resize_cmt(struct pt_regs *regs)
//{
//	struct task_struct *tsk;
//	unsigned long addr, cause;
//
//	cause = regs->cause;
//	addr = regs->badaddr;
//	tsk = current;
//
//  unsigned long config = tsk->dpt_config;
//	void *base_addr = (void *) (config & 0xFFFFFFFFFFFF);
//  unsigned long num_ways = (config >> 48) & 0xFFF; // config[59:48]
//  unsigned long size = 8 * ((size_t) 1 << DPT_TAG_WIDTH) * num_ways;
//	unsigned long new_num_ways;
//	if (num_ways < 16)
//		new_num_ways = num_ways * 2;
//	else
//		new_num_ways = num_ways + 8;
//
//  pr_alert("[DPT] Resize CMT! base_addr: 0x%lx num_ways: (0x%lx->0x%lx) addr: 0x%lx cause: 0x%lx\n",
//           	base_addr, num_ways, new_num_ways, addr, cause);
//
//
//  unsigned long num_rows = ((unsigned long) 1 << DPT_TAG_WIDTH);
//  unsigned long row_size = 8*num_ways;
//  //unsigned long bulk_size = 2048; // 4KB / 2
//  //unsigned long bulk_num = (num_rows * row_size) / bulk_size;
//  //unsigned long num_rows_per_bulk = (bulk_size / row_size);
//  unsigned long i, j;
//  void *kbuf = kmalloc(row_size, GFP_KERNEL);
//  //void *kbuf = kmalloc(bulk_size*2, GFP_KERNEL);
//  void *zero = kzalloc(row_size, GFP_KERNEL);
//
//  if (kbuf == NULL)
//  	pr_alert("DPT Failed kmalloc()!\n");
//
//  if (zero == NULL)
//  	pr_alert("DPT Failed kzalloc()!\n");
//
//  long err;
//  for (i=num_rows-1; i>0; i--) {
//    void *src = (void *) ((size_t) base_addr + ((i * num_ways) << 3));
//    void *dest = (void *) ((size_t) base_addr + ((i * new_num_ways) << 3));
//    //pr_alert("[DPT] i: 0x%lx src: %p dest: %p\n", i, src, dest);
//
//    err = __copy_from_user(kbuf, src, row_size);
//    //if (err != 0)
//    //  pr_alert("Error in copy from user\n");
//    err = __copy_to_user(dest, kbuf, row_size);
//    //if (err != 0)
//    //  pr_alert("Error in copy to user (1)\n");
//    err = __copy_to_user(src, zero, row_size);
//    //if (err != 0)
//    //  pr_alert("Error in copy to user (2)\n");
//  }
//
//  kfree(kbuf);
//  kfree(zero);
//
//	// Set DPT Config
//	unsigned long new_config = (((u_int64_t) 0x1 << 62) | // enableDPT
//													((u_int64_t) 0x1 << 61) | // enableStats
//													((u_int64_t) new_num_ways << 48) |
//													((u_int64_t) base_addr << 0));
//
//	current->dpt_config = new_config;
//	csr_write(CSR_DPT_CONFIG, new_config); // Enable DPT
//	pr_alert("[DPT] Finished CMT resizing!\n");
//
//	return;
//}
//yh+end
