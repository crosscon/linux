// Linux headers
#include <linux/fs.h> // Because this is a character device
#include <linux/miscdevice.h> // For the MISC_DYNAMIC_MINOR macro and the miscdevice struct
#include <linux/stat.h> // Has permission macros
#include <linux/module.h> // Contains the THIS_MODULE macro
#include <linux/mutex.h> // Declares the mutex
#include <linux/slab.h> // Kmalloc/kfree
#include <linux/uaccess.h> // copy_from_user and copy_to_user
#include <linux/dma-mapping.h> // dma_alloc_*, dma_free
#include <asm/uaccess.h> // access_ok
#include <linux/list.h> // The linked list
#include <linux/io.h>
#include <linux/dma-direct.h>

#include "cma_malloc.h" // Contains module specific information like magic number

/**
 * YOU DO NOT WANT TO USE CMA LIKE THIS
 *
 * There is no good reason to have physically continious memory unless a different device is involved.
 * If a different device is involved, you want to write a driver.
 *
 * This code is a nice exercise and can be used while developing hardware. Try not to use it in production.
 *
 * The code can be made nicer with kref, mmap open and mmap close callback functions.
 * This is omitted here because it is not worth the effort for now.
 * This also means that resource leaking on process crash is basically a given.
 * The file drivers/rapidio/devices/rio_mport_cdev.c gives a nice example of proper resource handling
 * No efforts to clean up are made when this module is removed from the kernel
 */

struct Allocation {
	dma_addr_t dma_handle;
	size_t size;
	void *cpu_addr;
	struct list_head list;
	struct task_struct *caller;
};
static DEFINE_MUTEX(
	allocationListLock); // allocationListLock protects allocationList and all of its items.
static struct device *dma_dev;
static LIST_HEAD(allocationList);

static long allocate(struct cma_space_request_struct *req)
{
	void *cpu_addr;
	dma_addr_t dma_handle;
	int retval;
	if (req->size % PAGE_SIZE != 0)
		return -EINVAL;
	cpu_addr =
		dma_alloc_noncoherent(dma_dev, req->size, &dma_handle, DMA_BIDIRECTIONAL, GFP_USER);
		printk("dma_alloc_noncoherent(0x%llx, 0x%llx, 0x%llx, %d, %x);\n",dma_dev, req->size, &dma_handle, DMA_BIDIRECTIONAL, GFP_USER);
	if (cpu_addr == NULL) {
		return -ENOMEM;
	} else {
		// Handle the new linked list item
		struct Allocation *alloc =
			kmalloc(sizeof(struct Allocation), GFP_KERNEL);
		alloc->dma_handle = dma_handle;
		alloc->size = req->size;
		alloc->cpu_addr = cpu_addr;
		alloc->caller = current;
		INIT_LIST_HEAD(&alloc->list);

		retval = mutex_lock_interruptible(&allocationListLock);
		if (unlikely(retval != 0)) {
			kfree(alloc);
			dma_free_noncoherent(dma_dev, req->size, cpu_addr,
					  dma_handle, DMA_BIDIRECTIONAL);
			return retval;
		}
		list_add(&alloc->list, &allocationList);
		mutex_unlock(&allocationListLock);

		req->real_addr = dma_handle;
		req->kern_addr = (uintptr_t)memremap(req->real_addr, req->size, MEMREMAP_WB);
		return 0;
	}
}

static long deallocate(dma_addr_t phys_addr)
{
	struct Allocation *alloc;
	struct Allocation *item = NULL;

	int retval = mutex_lock_interruptible(&allocationListLock);
	if (unlikely(retval != 0))
		return retval;
	list_for_each_entry (alloc, &allocationList, list) {
		if (alloc->dma_handle == phys_addr) {
			item = alloc;
			break;
		}
	}
	if (item != NULL && item->caller == current)
		list_del(&item->list);
	mutex_unlock(&allocationListLock);

	if (item != NULL && item->caller == current) {
		dma_free_noncoherent(dma_dev, item->size, item->cpu_addr,
				  item->dma_handle, DMA_BIDIRECTIONAL);
		kfree(item);
		return 0;
	} else {
		return -EINVAL;
	}
}

static long cma_malloc_ioctl(struct file *fptr, const unsigned int cmd,
			     const unsigned long arg)
{
	struct cma_space_request_struct *userReq, req;
	long retval;
	userReq = (void *)arg;
	if (!access_ok(userReq, sizeof(struct cma_space_request_struct)))
		return -EFAULT;
	if (copy_from_user(&req, userReq,
			   sizeof(struct cma_space_request_struct)) != 0)
		return -EBADE;
	switch (cmd) {
	case CMA_MALLOC_ALLOC:
		retval = allocate(&req);
		if (retval == 0) {
			if (copy_to_user(
				    userReq, &req,
				    sizeof(struct cma_space_request_struct)) !=
			    0)
				return -EBADE;
		}
		return retval;
	case CMA_MALLOC_FREE:
		return deallocate(req.real_addr);
	default:
		return -EINVAL;
		break;
	}
	return retval;
}

static int cma_malloc_mmap(struct file *fptr, struct vm_area_struct *vma)
{
	int retval;
	int found = 0;
	const struct Allocation *alloc;
	dma_addr_t dma_handle = vma->vm_pgoff << PAGE_SHIFT;
	size_t size = vma->vm_end - vma->vm_start;

	retval = mutex_lock_interruptible(&allocationListLock);
	if (unlikely(retval != 0))
		return retval;
	list_for_each_entry (alloc, &allocationList, list) {
		if (alloc->dma_handle <= dma_handle &&
		    alloc->dma_handle + alloc->size >= dma_handle) {
			found = 1;
			if (current != alloc->caller) {
				retval = -EINVAL;
			} else {
				retval = 0;
			}
			break;
		}
	}
	mutex_unlock(&allocationListLock);
	if (found == 0)
		return -EINVAL;
	if (retval != 0)
		return retval;

	dma_handle -= alloc->dma_handle;
	if (dma_handle + size > alloc->size)
		return -EINVAL;
	vma->vm_pgoff = dma_handle >> PAGE_SHIFT;
	unsigned long pfn = PHYS_PFN(dma_to_phys(dma_dev, alloc->dma_handle));
	retval = io_remap_pfn_range(vma, vma->vm_start, pfn, alloc->size, vma->vm_page_prot);
	return retval;
}

static struct file_operations cma_malloc_fileops = { .owner = THIS_MODULE,
						     .unlocked_ioctl =
							     cma_malloc_ioctl,
						     .mmap = cma_malloc_mmap };

static struct miscdevice cma_malloc_miscdevice = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = CMA_MALLOC_DEVICE_FILENAME,
	.fops = &cma_malloc_fileops,
	.mode = S_IRUGO | S_IWUGO,
};

static int __init cma_malloc_init(void)
{
	int ret;
	ret = misc_register(&cma_malloc_miscdevice);
	if (unlikely(ret)) {
		printk("Misc register failed: %d\n", ret);
	} else {
		dma_dev = cma_malloc_miscdevice.this_device;
		dma_dev->coherent_dma_mask = DMA_BIT_MASK(32);
		dma_dev->dma_mask = &dma_dev->coherent_dma_mask;
	}
	/*Enable user-mode access to counters. */
	asm volatile("msr pmuserenr_el0, %0" : : "r"(0b1111));

	/*   Performance Monitors Count Enable Set register bit 30:0 disable, 31 enable. Can also enable other event counters here. */ 
	asm volatile("msr pmcntenset_el0, %0" : : "r" (1<<32));

	/* Enable counters */
	u64 val=0;
	asm volatile("mrs %0, pmcr_el0" : "=r" (val));
	asm volatile("msr pmcr_el0, %0" : : "r" (val|1));

	asm volatile("mrs %0, PMCEID0_EL0" : : "r" (val));
	printk("PMCEID0_EL0 = 0x%lx", val);
	asm volatile("mrs %0, PMCEID1_EL0" : : "r" (val));
	printk("PMCEID1_EL0 = 0x%lx", val);


	return ret;
}

static void __exit cma_malloc_exit(void)
{
	misc_deregister(&cma_malloc_miscdevice);
}

module_init(cma_malloc_init);
module_exit(cma_malloc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("J. A. Dirks <jacko.dirks@gmail.com>");
MODULE_DESCRIPTION(
	"Provides a way to pass a chunk of CMA space to userspace, including its physical address");
MODULE_VERSION("1.0");
