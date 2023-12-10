#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <asm/csr.h>
#include <asm/io.h>

//SYSCALL_DEFINE2(dpt_set, unsigned long, config, void *, base) {
//SYSCALL_DEFINE3(dpt_set, long unsigned int, cmt_base, long unsigned int, num_ways, long unsigned int, wpb_base) {
SYSCALL_DEFINE2(dpt_set, long unsigned int, dpt_config, long unsigned int, wpb_base) {
  //printk("[DPT-SYSCALL] cmt_base: 0x%lx num_ways: 0x%lu wpb_base: 0x%lx\n",
  //        cmt_base, num_ways, wpb_base);
  printk("[DPT-SYSCALL] dpt_config: 0x%lx wpb_base: 0x%lx\n", dpt_config, wpb_base);

  csr_write(CSR_NUM_TAGD, 0);
  csr_write(CSR_NUM_XTAG, 0);
  csr_write(CSR_NUM_STORE, 0);
  csr_write(CSR_NUM_LOAD, 0);
  csr_write(CSR_NUM_TAGGED_STORE, 0);
  csr_write(CSR_NUM_TAGGED_LOAD, 0);
  csr_write(CSR_NUM_INST, 0);
  csr_write(CSR_LDST_TRAFFIC, 0);
  csr_write(CSR_BOUNDS_TRAFFIC, 0);
  csr_write(CSR_NUM_STORE_HIT, 0);
  csr_write(CSR_NUM_LOAD_HIT, 0);
  csr_write(CSR_NUM_CSTR, 0);
  csr_write(CSR_NUM_CCLR, 0);
  csr_write(CSR_BND_MASK, 0);

  csr_write(CSR_NUM_WAYS0, 0x101010101010101);
  csr_write(CSR_NUM_WAYS1, 0x101010101010101);
  csr_write(CSR_NUM_WAYS2, 0x101010101010101);
  csr_write(CSR_NUM_WAYS3, 0x101010101010101);
  //csr_write(CSR_ARENA_END0, 0x0000000000004000);
  //csr_write(CSR_ARENA_END1, 0x0000000000000000);
  //csr_write(CSR_ARENA_END2, 0x0000000000000000);
  //csr_write(CSR_ARENA_END3, 0x0000000000000000);
  //csr_write(CSR_ARENA_END4, 0x0000000000000000);
  //csr_write(CSR_ARENA_END5, 0x0000000000000000);
  //csr_write(CSR_ARENA_END6, 0x0000000000000000);
  //csr_write(CSR_ARENA_END7, 0x0000000000000000);
  csr_write(CSR_NUM_SLQ_ITR, 0);
  csr_write(CSR_NUM_SSQ_ITR, 0);
  csr_write(CSR_NUM_SCQ_ITR, 0);

  /* Set task struct with info */
  current->dpt_config = dpt_config;
  current->wpb_base = wpb_base;
  csr_write(CSR_WPB_BASE, wpb_base);
  csr_write(CSR_DPT_CONFIG, dpt_config);

  printk("[DPT-SYSCALL] Finished! config: 0x%lx\n", dpt_config);

  return 0;
}

SYSCALL_DEFINE2(arena_set, long unsigned int, arena_num, long unsigned int, arena_val) {
  if (arena_num == 0) {
    csr_write(CSR_ARENA_END0, arena_val);
    current->arena_end0 = arena_val;
  } else if (arena_num == 1) {
    csr_write(CSR_ARENA_END1, arena_val);
    current->arena_end1 = arena_val;
  } else if (arena_num == 2) {
    csr_write(CSR_ARENA_END2, arena_val);
    current->arena_end2 = arena_val;
  } else if (arena_num == 3) {
    csr_write(CSR_ARENA_END3, arena_val);
    current->arena_end3 = arena_val;
  } else if (arena_num == 4) {
    csr_write(CSR_ARENA_END4, arena_val);
    current->arena_end4 = arena_val;
  } else if (arena_num == 5) {
    csr_write(CSR_ARENA_END5, arena_val);
    current->arena_end5 = arena_val;
  } else if (arena_num == 6) {
    csr_write(CSR_ARENA_END6, arena_val);
    current->arena_end6 = arena_val;
  } else if (arena_num == 7) {
    csr_write(CSR_ARENA_END7, arena_val);
    current->arena_end7 = arena_val;
  } else {
    printk("[DPT-ARENA] Unsupported arena_num! (%d)\n", arena_num);
  }

  long unsigned int dpt_config = (long unsigned int) csr_read(CSR_DPT_CONFIG);
//  printk("[DPT-ARENA] Update arena_num: %lu arena_val: 0x%lx dpt_config: (0x%lx -> 0x%lx)\n",
//	  arena_num, arena_val, dpt_config, (dpt_config & ~((size_t) 1 << 57)));
  dpt_config = (dpt_config & ~((size_t) 1 << 57));
  csr_write(CSR_DPT_CONFIG, dpt_config);
  current->dpt_config = dpt_config;

  return 0;
}
