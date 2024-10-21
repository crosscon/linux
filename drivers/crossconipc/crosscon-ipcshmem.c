/**
 * TODO: licsense
 */

/* #include "printk.h" */
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/of.h>
#include <asm/io.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/platform_device.h>
#include <linux/ioctl.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/mm.h>

#if defined(CONFIG_ARM64) || defined(CONFIG_ARM)
#include <linux/arm-smccc.h>
#include <asm/memory.h>
#elif CONFIG_RISCV
#include <asm/sbi.h>
#endif

#define DEV_NAME "crossconhypipc"
#define MAX_DEVICES 16
#define NAME_LEN 32

static dev_t crossconhyp_ipcshmem_devt;
static struct class *cl;

struct crossconhyp_ipcshmem
{
    struct cdev cdev;
    struct device *dev;

    int id;
    char label[NAME_LEN];
    void* read_base;
    size_t read_size;
    void* write_base;
    size_t write_size;
    void* physical_base;
};

#ifdef CONFIG_ARM64
static uint64_t crossconhyp_ipcshmem_notify(struct crossconhyp_ipcshmem *dev) {
    register uint64_t x0 asm("x0") = ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL,
                ARM_SMCCC_SMC_64, ARM_SMCCC_OWNER_VENDOR_HYP, 1);
    register uint64_t x1 asm("x1") = dev->id;
    register uint64_t x2 asm("x2") = 0;

    asm volatile(
        "hvc 0\t\n"
        : "=r"(x0)
        : "r"(x0), "r"(x1), "r"(x2)
    );

    return x0;
}
#elif CONFIG_ARM
static uint32_t crossconhyp_ipcshmem_notify(struct crossconhyp_ipcshmem *dev) {
    register uint32_t r0 asm("r0") = ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL,
                ARM_SMCCC_SMC_32, ARM_SMCCC_OWNER_VENDOR_HYP, 1);
    register uint32_t r1 asm("r1") = dev->id;
    register uint32_t r2 asm("r2") = 0;

    asm volatile(
        "hvc #0\t\n"
        : "=r"(r0)
        : "r"(r0), "r"(r1), "r"(r2)
    );

    return r0;
}
#elif CONFIG_RISCV
static uint64_t crossconhyp_ipcshmem_notify(struct crossconhyp_ipcshmem *dev) {

	struct sbiret ret =
		sbi_ecall(0x08000ba0, 1, dev->id, 0, 0, 0, 0, 0);

	return ret.error;
}
#endif

static ssize_t crossconhyp_ipcshmem_read_fops(struct file *filp,
                           char *buf, size_t count, loff_t *ppos)
{
    struct crossconhyp_ipcshmem *ipcshmem = filp->private_data;
    unsigned long missing = 0;
    size_t len = 0;

    len = strnlen(ipcshmem->read_base, ipcshmem->read_size);

    if (*ppos >= len) return 0;
    if ((len - *ppos) < count) count = len - *ppos;

    missing =
        copy_to_user(buf, ipcshmem->read_base + *ppos, count);
    if(missing != 0) count = count - missing;
    *ppos += count;

    return count;
}

static ssize_t crossconhyp_ipcshmem_write_fops(struct file *filp,
                            const char *buf, size_t count, loff_t *ppos)
{
    struct crossconhyp_ipcshmem *ipcshmem = filp->private_data;
    unsigned long missing = 0;

    if (*ppos >= ipcshmem->write_size)
        return 0;
    if(count > ipcshmem->write_size)
        count = ipcshmem->write_size;
    if((*ppos + count) > ipcshmem->write_size)
        count = ipcshmem->write_size - *ppos;

    missing =
        copy_from_user(ipcshmem->write_base + *ppos, buf, count);
    if (missing != 0) {
        count = count - missing;
        pr_info("some bytes missing %d", missing);
    }
    *ppos += count;

    crossconhyp_ipcshmem_notify(ipcshmem);

    return count;
}

static int crossconhyp_ipcshmem_mmap_fops(struct file *filp, struct vm_area_struct *vma)
{
    struct crossconhyp_ipcshmem *crossconhyp = filp->private_data;

    unsigned long vsize = vma->vm_end - vma->vm_start;

    if (remap_pfn_range(vma, vma->vm_start,
            (unsigned long)crossconhyp->physical_base >> PAGE_SHIFT, vsize,
            vma->vm_page_prot)) {
        printk(KERN_ERR "failed to remap physical address of shmem\n");
        return -EFAULT;
    }

    return 0;
}

static int crossconhyp_ipcshmem_open_fops(struct inode *inode, struct file *filp)
{
    struct crossconhyp_ipcshmem *crossconhyp_ipcshmem = container_of(inode->i_cdev,
                                             struct crossconhyp_ipcshmem, cdev);
    filp->private_data = crossconhyp_ipcshmem;

    kobject_get(&crossconhyp_ipcshmem->dev->kobj);

    return 0;
}

static int crossconhyp_ipcshmem_release_fops(struct inode *inode, struct file *filp)
{
    struct crossconhyp_ipcshmem *crossconhyp_ipcshmem = container_of(inode->i_cdev,
                                             struct crossconhyp_ipcshmem, cdev);
    filp->private_data = NULL;

    kobject_put(&crossconhyp_ipcshmem->dev->kobj);

    return 0;
}

static struct file_operations crossconhyp_ipcshmem_fops = {
    .owner = THIS_MODULE,
    .read = crossconhyp_ipcshmem_read_fops,
    .write = crossconhyp_ipcshmem_write_fops,
    .mmap = crossconhyp_ipcshmem_mmap_fops,
    .open = crossconhyp_ipcshmem_open_fops,
    .release = crossconhyp_ipcshmem_release_fops
};

int crossconhyp_ipcshmem_register(struct platform_device *pdev)
{
    int ret = 0;
    struct device *dev = &(pdev->dev);
    struct device_node *np = dev->of_node;
    struct module *owner = THIS_MODULE;
    struct resource *r;
    dev_t devt;
	resource_size_t shmem_size;
    u32 write_offset, read_offset, write_size, read_size;
    bool rd_in_range, wr_in_range, disjoint;
    void* shmem_base_addr = NULL;
    int id = -1;
    struct crossconhyp_ipcshmem *crossconhyp;

    r = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if(r == NULL)
		return -EINVAL;
    of_property_read_u32_index(np, "read-channel", 0, &read_offset);
    of_property_read_u32_index(np, "read-channel", 1, &read_size);
    of_property_read_u32_index(np, "write-channel", 0, &write_offset);
    of_property_read_u32_index(np, "write-channel", 1, &write_size);

    rd_in_range = (r->start + read_offset + read_size) < r->end;
    wr_in_range =  (r->start + write_offset + write_size) < r->end;
    disjoint = ((read_offset + read_size) <= write_offset) ||
        ((write_offset + write_size) <= read_offset);

    if(!rd_in_range || !wr_in_range || !disjoint) {
        dev_err(&pdev->dev,"invalid channel layout\n");
        dev_err(&pdev->dev,"rd_in_range = %d, wr_in_range = %d, disjoint = %d\n",
            rd_in_range, wr_in_range, disjoint);
        return -EINVAL;
    }

    shmem_size = r->end - r->start + 1;
	shmem_base_addr = memremap(r->start, shmem_size, MEMREMAP_WB);
	if(shmem_base_addr == NULL)
		return -ENOMEM;

    of_property_read_u32(np, "id", &id);
    if (id >= MAX_DEVICES) {
        dev_err(&pdev->dev,"invalid id %d\n", id);
        ret = -EINVAL;
        goto err_unmap;
    }

    crossconhyp = devm_kzalloc(&pdev->dev, sizeof(struct crossconhyp_ipcshmem), GFP_KERNEL);
    if(crossconhyp == NULL) {
        ret = -ENOMEM;
        goto err_unmap;
    }
    snprintf(crossconhyp->label, NAME_LEN, "%s%d", DEV_NAME, id);
    crossconhyp->id = id;
    crossconhyp->read_size = read_size;
    crossconhyp->write_size = write_size;
    crossconhyp->read_base = shmem_base_addr + read_offset;
    crossconhyp->write_base = shmem_base_addr + write_offset;
    crossconhyp->physical_base = (void *)r->start;

    cdev_init(&crossconhyp->cdev, &crossconhyp_ipcshmem_fops);
    crossconhyp->cdev.owner = owner;

    devt = MKDEV(MAJOR(crossconhyp_ipcshmem_devt), id);
    ret = cdev_add(&crossconhyp->cdev, devt, 1);
    if (ret) {
        goto err_unmap;
    }

    crossconhyp->dev = device_create(cl, &pdev->dev, devt, crossconhyp, crossconhyp->label);
    if (IS_ERR(crossconhyp->dev)) {
        ret = PTR_ERR(crossconhyp->dev);
        goto err_cdev;
    }
    dev_set_drvdata(crossconhyp->dev, crossconhyp);

    return 0;

err_cdev:
    cdev_del(&crossconhyp->cdev);
err_unmap:
    memunmap(shmem_base_addr);

    dev_err(&pdev->dev,"failed initialization\n");
    return ret;
}

static int crossconhyp_ipcshmem_unregister(struct platform_device *pdev)
{
    /* TODO */
    return 0;
}

static const struct of_device_id of_crossconhyp_ipcshmem_match[] = {
    {
        .compatible = "crossconhyp,ipcshmem",
    },
    {/* sentinel */}};
MODULE_DEVICE_TABLE(of, of_crossconhyp_ipcshmem_match);

static struct platform_driver crossconhyp_ipcshmem_driver = {
    .probe = crossconhyp_ipcshmem_register,
    .remove = crossconhyp_ipcshmem_unregister,
    .driver = {
        .name = DEV_NAME,
        .of_match_table = of_crossconhyp_ipcshmem_match,
    },
};

static int __init crossconhyp_ipcshmem_init(void)
{
    int ret;

    if ((cl = class_create(THIS_MODULE, DEV_NAME)) == NULL) {
        ret = -1;
        pr_err("unable to class_create " DEV_NAME " device\n");
        return ret;
    }

    ret = alloc_chrdev_region(&crossconhyp_ipcshmem_devt, 0, MAX_DEVICES, DEV_NAME);
    if (ret < 0) {
        pr_err("unable to alloc_chrdev_region " DEV_NAME " device\n");
        return ret;
    }

    return platform_driver_register(&crossconhyp_ipcshmem_driver);
}

static void __exit crossconhyp_ipcshmem_exit(void)
{
    platform_driver_unregister(&crossconhyp_ipcshmem_driver);
    unregister_chrdev(crossconhyp_ipcshmem_devt, DEV_NAME);
    class_destroy(cl);
}

module_init(crossconhyp_ipcshmem_init);
module_exit(crossconhyp_ipcshmem_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("David Cerdeira");
MODULE_AUTHOR("José Martins");
MODULE_DESCRIPTION("crossconhyp ipc through shared-memory sample driver");
