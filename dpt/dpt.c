#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <asm/csr.h>
#include <asm/io.h>

SYSCALL_DEFINE2(dpt_set, unsigned long, config, void *, base) {
  printk("[DPT-SYSCALL] config: 0x%lx base: 0x%lx\n", config, base);

	//csr_write(CSR_BOUNDS_MARGIN, 0);
	csr_write(CSR_NUM_TAGD, 0);
	csr_write(CSR_NUM_XTAG, 0);
	csr_write(CSR_NUM_TAGGED_STORE, 0);
	csr_write(CSR_NUM_UNTAGGED_STORE, 0);
	csr_write(CSR_NUM_TAGGED_LOAD, 0);
	csr_write(CSR_NUM_UNTAGGED_LOAD, 0);
	csr_write(CSR_NUM_INST, 0);
	csr_write(CSR_LDST_TRAFFIC, 0);
	csr_write(CSR_BOUNDS_TRAFFIC, 0);
	csr_write(CSR_NUM_STORE_HIT, 0);
	csr_write(CSR_NUM_LOAD_HIT, 0);
	csr_write(CSR_NUM_CSTR, 0);
	csr_write(CSR_NUM_CCLR, 0);
	csr_write(CSR_NUM_CSRCH, 0);
	//csr_write(CSR_NUM_CSRCH_HIT, 0);
	//csr_write(CSR_NUM_CSTR_ITR, 0);
	//csr_write(CSR_NUM_CCLR_ITR, 0);
	//csr_write(CSR_NUM_CSRCH_ITR, 0);
	//csr_write(CSR_NUM_CHK_FAIL, 0);
	//csr_write(CSR_NUM_CSTR_FAIL, 0);
	//csr_write(CSR_NUM_CCLR_FAIL, 0);

  /* Set task struct with info */
  current->dpt_config = config;
	csr_write(CSR_DPT_CONFIG, config);

  return 0;
}
