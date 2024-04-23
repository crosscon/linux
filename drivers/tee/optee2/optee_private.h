/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2015, Linaro Limited
 */

#ifndef OPTEE2_PRIVATE_H
#define OPTEE2_PRIVATE_H

#if defined(CONFIG_HAVE_ARM_SMCCC)
#include <linux/arm-smccc.h>
#include "optee_smc.h"
#elif defined(CONFIG_RISCV_SBI)
#include "optee_sbi.h"
#endif
#include <linux/semaphore.h>
#include <linux/tee_drv.h>
#include <linux/types.h>
#include "optee_msg.h"


#define OPTEE2_MAX_ARG_SIZE	1024

/* Some Global Platform error codes used in this driver */
#define TEEC_SUCCESS			0x00000000
#define TEEC_ERROR_BAD_PARAMETERS	0xFFFF0006
#define TEEC_ERROR_NOT_SUPPORTED	0xFFFF000A
#define TEEC_ERROR_COMMUNICATION	0xFFFF000E
#define TEEC_ERROR_OUT_OF_MEMORY	0xFFFF000C
#define TEEC_ERROR_SHORT_BUFFER		0xFFFF0010

#define TEEC_ORIGIN_COMMS		0x00000002

typedef void (optee2_invoke_fn)(unsigned long, unsigned long, unsigned long,
				unsigned long, unsigned long, unsigned long,
				unsigned long, unsigned long,
				optee2_res_t *);

struct optee2_call_queue {
	/* Serializes access to this struct */
	struct mutex mutex;
	struct list_head waiters;
};

struct optee2_wait_queue {
	/* Serializes access to this struct */
	struct mutex mu;
	struct list_head db;
};

/**
 * struct optee2_supp - supplicant synchronization struct
 * @ctx			the context of current connected supplicant.
 *			if !NULL the supplicant device is available for use,
 *			else busy
 * @mutex:		held while accessing content of this struct
 * @req_id:		current request id if supplicant is doing synchronous
 *			communication, else -1
 * @reqs:		queued request not yet retrieved by supplicant
 * @idr:		IDR holding all requests currently being processed
 *			by supplicant
 * @reqs_c:		completion used by supplicant when waiting for a
 *			request to be queued.
 */
struct optee2_supp {
	/* Serializes access to this struct */
	struct mutex mutex;
	struct tee_context *ctx;

	int req_id;
	struct list_head reqs;
	struct idr idr;
	struct completion reqs_c;
};

/**
 * struct optee2 - main service struct
 * @supp_teedev:	supplicant device
 * @teedev:		client device
 * @invoke_fn:		function to issue smc or hvc
 * @call_queue:		queue of threads waiting to call @invoke_fn
 * @wait_queue:		queue of threads from secure world waiting for a
 *			secure world sync object
 * @supp:		supplicant synchronization struct for RPC to supplicant
 * @pool:		shared memory pool
 * @memremaped_shm	virtual address of memory in shared memory pool
 * @sec_caps:		secure world capabilities defined by
 *			OPTEE2_SMC_SEC_CAP_* in optee2_smc.h
 * @scan_bus_done	flag if device registation was already done.
 * @scan_bus_wq		workqueue to scan optee2 bus and register optee2 drivers
 * @scan_bus_work	workq to scan optee2 bus and register optee2 drivers
 */
struct optee2 {
	struct tee_device *supp_teedev;
	struct tee_device *teedev;
	optee2_invoke_fn *invoke_fn;
	struct optee2_call_queue call_queue;
	struct optee2_wait_queue wait_queue;
	struct optee2_supp supp;
	struct tee_shm_pool *pool;
	void *memremaped_shm;
	u32 sec_caps;
	bool   scan_bus_done;
	struct workqueue_struct *scan_bus_wq;
	struct work_struct scan_bus_work;
};

struct optee2_session {
	struct list_head list_node;
	u32 session_id;
};

struct optee2_context_data {
	/* Serializes access to this struct */
	struct mutex mutex;
	struct list_head sess_list;
};

struct optee2_rpc_param {
	u32	a0;
	u32	a1;
	u32	a2;
	u32	a3;
	u32	a4;
	u32	a5;
	u32	a6;
	u32	a7;
};

/* Holds context that is preserved during one STD call */
struct optee2_call_ctx {
	/* information about pages list used in last allocation */
	void *pages_list;
	size_t num_entries;
};

void optee2_handle_rpc(struct tee_context *ctx, struct optee2_rpc_param *param,
		      struct optee2_call_ctx *call_ctx);
void optee2_rpc_finalize_call(struct optee2_call_ctx *call_ctx);

void optee2_wait_queue_init(struct optee2_wait_queue *wq);
void optee2_wait_queue_exit(struct optee2_wait_queue *wq);

u32 optee2_supp_thrd_req(struct tee_context *ctx, u32 func, size_t num_params,
			struct tee_param *param);

int optee2_supp_read(struct tee_context *ctx, void __user *buf, size_t len);
int optee2_supp_write(struct tee_context *ctx, void __user *buf, size_t len);
void optee2_supp_init(struct optee2_supp *supp);
void optee2_supp_uninit(struct optee2_supp *supp);
void optee2_supp_release(struct optee2_supp *supp);

int optee2_supp_recv(struct tee_context *ctx, u32 *func, u32 *num_params,
		    struct tee_param *param);
int optee2_supp_send(struct tee_context *ctx, u32 ret, u32 num_params,
		    struct tee_param *param);

u32 optee2_do_call_with_arg(struct tee_context *ctx, phys_addr_t parg);
int optee2_open_session(struct tee_context *ctx,
		       struct tee_ioctl_open_session_arg *arg,
		       struct tee_param *param);
int optee2_close_session(struct tee_context *ctx, u32 session);
int optee2_invoke_func(struct tee_context *ctx, struct tee_ioctl_invoke_arg *arg,
		      struct tee_param *param);
int optee2_cancel_req(struct tee_context *ctx, u32 cancel_id, u32 session);

void optee2_enable_shm_cache(struct optee2 *optee2);
void optee2_disable_shm_cache(struct optee2 *optee2);

int optee2_shm_register(struct tee_context *ctx, struct tee_shm *shm,
		       struct page **pages, size_t num_pages,
		       unsigned long start);
int optee2_shm_unregister(struct tee_context *ctx, struct tee_shm *shm);

int optee2_shm_register_supp(struct tee_context *ctx, struct tee_shm *shm,
			    struct page **pages, size_t num_pages,
			    unsigned long start);
int optee2_shm_unregister_supp(struct tee_context *ctx, struct tee_shm *shm);

int optee2_from_msg_param(struct tee_param *params, size_t num_params,
			 const struct optee2_msg_param *msg_params);
int optee2_to_msg_param(struct optee2_msg_param *msg_params, size_t num_params,
		       const struct tee_param *params);

u64 *optee2_allocate_pages_list(size_t num_entries);
void optee2_free_pages_list(void *array, size_t num_entries);
void optee2_fill_pages_list(u64 *dst, struct page **pages, int num_pages,
			   size_t page_offset);

#define PTA_CMD_GET_DEVICES		0x0
#define PTA_CMD_GET_DEVICES_SUPP	0x1
int optee2_enumerate_devices(u32 func);

/*
 * Small helpers
 */

static inline void *reg_pair_to_ptr(u32 reg0, u32 reg1)
{
	return (void *)(unsigned long)(((u64)reg0 << 32) | reg1);
}

static inline void reg_pair_from_64(u32 *reg0, u32 *reg1, u64 val)
{
	*reg0 = val >> 32;
	*reg1 = val;
}

#endif /*OPTEE2_PRIVATE_H*/
