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
  csr_write(CSR_ARENA_END0, 0x2000200020002000);
  csr_write(CSR_ARENA_END1, 0x2000200020002000);
  csr_write(CSR_ARENA_END2, 0x2000200020002000);
  csr_write(CSR_ARENA_END3, 0x2000200020002000);
  csr_write(CSR_ARENA_END4, 0x2000200020002000);
  csr_write(CSR_ARENA_END5, 0x2000200020002000);
  csr_write(CSR_ARENA_END6, 0x2000200020002000);
  csr_write(CSR_ARENA_END7, 0xFFFF200020002000);

  /* Set task struct with info */
  //long unsigned int dpt_config = (((long unsigned int) 0x1 << 62) | // enableDPT
  //                        ((long unsigned int) 0x1 << 61) | // enableStats
  //                        ((long unsigned int) num_ways << 48) |
  //                        ((long unsigned int) cmt_base << 0));
  current->dpt_config = dpt_config;
  current->wpb_base = wpb_base;
  csr_write(CSR_WPB_BASE, wpb_base);
  csr_write(CSR_DPT_CONFIG, dpt_config);

  printk("[DPT-SYSCALL] Finished! config: 0x%lx\n", dpt_config);

  return 0;
}
