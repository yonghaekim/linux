/* Remember: mmap, like most fops, does not work with debugfs as of 4.9! https://patchwork.kernel.org/patch/9252557/

Adapted from:
https://coherentmusings.wordpress.com/2014/06/10/implementing-mmap-for-transferring-data-from-user-space-to-kernel-space/
*/

#include <linux/uaccess.h> /* copy_from_user */
#include <asm/io.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h> /* min */
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>

// Default to only malloc 1 page 
int page_order = 10;
//module_param(page_order, int, 0);

static const char *filename = "centrifuge_mmap";
unsigned long kaddr = 0;
char *buf;

static int mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long pfn;
	pfn = virt_to_phys((void*)kaddr) >> PAGE_SHIFT;

	if(remap_pfn_range(vma, vma->vm_start, pfn, (vma->vm_end - vma->vm_start),
							vma->vm_page_prot))
	{
			printk("remap failed...");
			return -1;
	}
	vma->vm_flags |= (VM_DONTDUMP|VM_DONTEXPAND);
	//printk("remap_pfn_rang pfn:[%lu] ok.\n", pfn);
	return 0;
}

static int release(struct inode *inode, struct file *filp)
{
	return 0;
}

static const struct file_operations fops = {
	.mmap = mmap,
  .release = release
};

static int myinit(void)
{
  int i;
	proc_create(filename, 0, NULL, &fops);
  /* alloc one page */

  // Allocate 64 MB memory
  for (i = 0; i < 16; i ++) {
	  //kaddr = __get_free_pages(GFP_KERNEL, page_order);
	  unsigned long kaddr_1 = __get_free_pages(GFP_KERNEL, page_order);
	  //unsigned long kaddr_2 = __get_free_pages(GFP_KERNEL, page_order);
	  printk("kaddr_1:[%lx] ok.\n", kaddr_1);
    if ((kaddr_1 !=  kaddr - 0x400000) && (i !=0)) {
      printk("Error");
      dump_stack(); 
      //BUG();
    } 
    kaddr = kaddr_1;
  }
	//printk("kaddr_1:[%lx] ok.\n", kaddr_1);
	//printk("kaddr_2:[%lx] ok.\n", kaddr_2);

	if (!kaddr) {
			printk("Allocate memory failure!/n");
	} else {
    //XXX This is techinically needed, but I'm lazy right now
    /* SetPageReserved(virt_to_page(kaddr)); */

    unsigned long MEMSZ = ((1 << page_order) * PAGE_SIZE);
    buf = (char *)kaddr;

    for(i = 0; i < MEMSZ; i += PAGE_SIZE) {
      sprintf(buf + i, "%d", i >> PAGE_SHIFT);
    }
    printk("Allocate memory success!.\n");
	}
	return 0;
}

static void myexit(void)
{
  pr_info("mmap2 module exiting\n");
	/* ClearPageReserved(virt_to_page(kaddr)); */
	free_pages(kaddr, page_order);
	remove_proc_entry(filename, NULL);
	return;
}

module_init(myinit)
module_exit(myexit)
MODULE_LICENSE("GPL");
