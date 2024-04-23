#ifndef _CROSSCON_H_
#define _CROSSCON_H_

#include <linux/ioctl.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/wait.h>

#define CROSSCONENCLAVE_DEVICE_IOCTL_BASE 'B'
#define CROSSCONENCLAVE_DEVICE_IOC_CREATE_CMA        _IOW(CROSSCONENCLAVE_DEVICE_IOCTL_BASE, 3, int)
#define CROSSCONENCLAVE_DEVICE_IOC_RESUME_ENCLAVE	_IOW(CROSSCONENCLAVE_DEVICE_IOCTL_BASE, 4, int)
#define CROSSCONENCLAVE_DEVICE_IOC_CALL_ENCLAVE	_IOW(CROSSCONENCLAVE_DEVICE_IOCTL_BASE, 5, int)
#define CROSSCONENCLAVE_DEVICE_IOC_DESTROY_ENCLAVE	_IOW(CROSSCONENCLAVE_DEVICE_IOCTL_BASE, 6, int)
#define CROSSCONENCLAVE_DEVICE_IOC_PRINT_INFO	_IOW(CROSSCONENCLAVE_DEVICE_IOCTL_BASE, 7, int)
#define CROSSCONENCLAVE_DEVICE_IOC_ADD_RGN		_IOW(CROSSCONENCLAVE_DEVICE_IOCTL_BASE, 8, int)
#define CROSSCONENCLAVE_DEVICE_IOC_RING 		_IOW(CROSSCONENCLAVE_DEVICE_IOCTL_BASE, 1, int)
#define CROSSCONENCLAVE_DEVICE_IOC_READ 		_IOR(CROSSCONENCLAVE_DEVICE_IOCTL_BASE, 0, int)

#define CROSSCON_ENCLAVE_DEVICE_NAME "crosscon_enclave"
#define MAX_DEVICES 1
#define NAME_LEN 32
#define BUF_LEN 0x1000

/* driver private data */
struct crossconenclave_shared_memory {
	uint64_t base;
	size_t size;
	struct resource *resource;
	char *ptr;
};

struct crossconenclave_device {
	struct cdev cdev;
	struct device *dev;

	/* ctrl */
	struct mutex mux;
	struct spinlock lock;
	wait_queue_head_t queue;

	/* priv data */
	int id;
	char label[NAME_LEN];
	int irq;
	int data_available;
	int busy;
	struct crossconenclave_shared_memory shared_memory;
	char buf[BUF_LEN];
};

int crossconenclave_device_register(const char *label, unsigned int id,
			       unsigned int irq, uint64_t base, uint64_t size,
			       struct module *owner, struct device *parent);

int crossconenclave_device_unregister(const char *label, unsigned int id);

#endif
