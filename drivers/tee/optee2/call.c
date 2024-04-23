// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2015, Linaro Limited
 */
#if defined(CONFIG_HAVE_ARM_SMCCC)
#include <linux/arm-smccc.h>
#endif
#include <linux/device.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/tee_drv.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include "optee_private.h"
#if defined(CONFIG_HAVE_ARM_SMCCC)
#include "optee_smc.h"
#elif defined(CONFIG_RISCV_SBI)
#include "optee_sbi.h"
#define virt_to_phys(x) __pa((x))
#endif


struct optee2_call_waiter {
	struct list_head list_node;
	struct completion c;
};

static void optee2_cq_wait_init(struct optee2_call_queue *cq,
			       struct optee2_call_waiter *w)
{
	/*
	 * We're preparing to make a call to secure world. In case we can't
	 * allocate a thread in secure world we'll end up waiting in
	 * optee2_cq_wait_for_completion().
	 *
	 * Normally if there's no contention in secure world the call will
	 * complete and we can cleanup directly with optee2_cq_wait_final().
	 */
	mutex_lock(&cq->mutex);

	/*
	 * We add ourselves to the queue, but we don't wait. This
	 * guarantees that we don't lose a completion if secure world
	 * returns busy and another thread just exited and try to complete
	 * someone.
	 */
	init_completion(&w->c);
	list_add_tail(&w->list_node, &cq->waiters);

	mutex_unlock(&cq->mutex);
}

static void optee2_cq_wait_for_completion(struct optee2_call_queue *cq,
					 struct optee2_call_waiter *w)
{
	wait_for_completion(&w->c);

	mutex_lock(&cq->mutex);

	/* Move to end of list to get out of the way for other waiters */
	list_del(&w->list_node);
	reinit_completion(&w->c);
	list_add_tail(&w->list_node, &cq->waiters);

	mutex_unlock(&cq->mutex);
}

static void optee2_cq_complete_one(struct optee2_call_queue *cq)
{
	struct optee2_call_waiter *w;

	list_for_each_entry(w, &cq->waiters, list_node) {
		if (!completion_done(&w->c)) {
			complete(&w->c);
			break;
		}
	}
}

static void optee2_cq_wait_final(struct optee2_call_queue *cq,
				struct optee2_call_waiter *w)
{
	/*
	 * We're done with the call to secure world. The thread in secure
	 * world that was used for this call is now available for some
	 * other task to use.
	 */
	mutex_lock(&cq->mutex);

	/* Get out of the list */
	list_del(&w->list_node);

	/* Wake up one eventual waiting task */
	optee2_cq_complete_one(cq);

	/*
	 * If we're completed we've got a completion from another task that
	 * was just done with its call to secure world. Since yet another
	 * thread now is available in secure world wake up another eventual
	 * waiting task.
	 */
	if (completion_done(&w->c))
		optee2_cq_complete_one(cq);

	mutex_unlock(&cq->mutex);
}

/* Requires the filpstate mutex to be held */
static struct optee2_session *find_session(struct optee2_context_data *ctxdata,
					  u32 session_id)
{
	struct optee2_session *sess;

	list_for_each_entry(sess, &ctxdata->sess_list, list_node)
		if (sess->session_id == session_id)
			return sess;

	return NULL;
}

/**
 * optee2_do_call_with_arg() - Do an SMC to OP-TEE in secure world
 * @ctx:	calling context
 * @parg:	physical address of message to pass to secure world
 *
 * Does and SMC to OP-TEE in secure world and handles eventual resulting
 * Remote Procedure Calls (RPC) from OP-TEE.
 *
 * Returns return code from secure world, 0 is OK
 */
u32 optee2_do_call_with_arg(struct tee_context *ctx, phys_addr_t parg)
{
	struct optee2 *optee2 = tee_get_drvdata(ctx->teedev);
	struct optee2_call_waiter w;
	struct optee2_rpc_param param = { };
	struct optee2_call_ctx call_ctx = { };
	u32 ret;

	param.a0 = OPTEE2_SMC_CALL_WITH_ARG;
	reg_pair_from_64(&param.a1, &param.a2, parg);
	/* Initialize waiter */
	optee2_cq_wait_init(&optee2->call_queue, &w);
	while (true) {
		optee2_res_t res;

		optee2->invoke_fn(param.a0, param.a1, param.a2, param.a3,
				 param.a4, param.a5, param.a6, param.a7,
				 &res);

		if (res.a0 == OPTEE2_SMC_RETURN_ETHREAD_LIMIT) {
			/*
			 * Out of threads in secure world, wait for a thread
			 * become available.
			 */
			optee2_cq_wait_for_completion(&optee2->call_queue, &w);
		} else if (OPTEE2_SMC_RETURN_IS_RPC(res.a0)) {
			if (need_resched())
				cond_resched();
			param.a0 = res.a0;
			param.a1 = res.a1;
			param.a2 = res.a2;
			param.a3 = res.a3;
			optee2_handle_rpc(ctx, &param, &call_ctx);
		} else {
			ret = res.a0;
			break;
		}
	}

	optee2_rpc_finalize_call(&call_ctx);
	/*
	 * We're done with our thread in secure world, if there's any
	 * thread waiters wake up one.
	 */
	optee2_cq_wait_final(&optee2->call_queue, &w);

	return ret;
}

static struct tee_shm *get_msg_arg(struct tee_context *ctx, size_t num_params,
				   struct optee2_msg_arg **msg_arg,
				   phys_addr_t *msg_parg)
{
	int rc;
	struct tee_shm *shm;
	struct optee2_msg_arg *ma;

	shm = tee_shm_alloc(ctx, OPTEE2_MSG_GET_ARG_SIZE(num_params),
			    TEE_SHM_MAPPED);
	if (IS_ERR(shm))
		return shm;

	ma = tee_shm_get_va(shm, 0);
	if (IS_ERR(ma)) {
		rc = PTR_ERR(ma);
		goto out;
	}

	rc = tee_shm_get_pa(shm, 0, msg_parg);
	if (rc)
		goto out;

	memset(ma, 0, OPTEE2_MSG_GET_ARG_SIZE(num_params));
	ma->num_params = num_params;
	*msg_arg = ma;
out:
	if (rc) {
		tee_shm_free(shm);
		return ERR_PTR(rc);
	}

	return shm;
}

int optee2_open_session(struct tee_context *ctx,
		       struct tee_ioctl_open_session_arg *arg,
		       struct tee_param *param)
{
	struct optee2_context_data *ctxdata = ctx->data;
	int rc;
	struct tee_shm *shm;
	struct optee2_msg_arg *msg_arg;
	phys_addr_t msg_parg;
	struct optee2_session *sess = NULL;

	/* +2 for the meta parameters added below */
	shm = get_msg_arg(ctx, arg->num_params + 2, &msg_arg, &msg_parg);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	msg_arg->cmd = OPTEE2_MSG_CMD_OPEN_SESSION;
	msg_arg->cancel_id = arg->cancel_id;

	/*
	 * Initialize and add the meta parameters needed when opening a
	 * session.
	 */
	msg_arg->params[0].attr = OPTEE2_MSG_ATTR_TYPE_VALUE_INPUT |
				  OPTEE2_MSG_ATTR_META;
	msg_arg->params[1].attr = OPTEE2_MSG_ATTR_TYPE_VALUE_INPUT |
				  OPTEE2_MSG_ATTR_META;
	memcpy(&msg_arg->params[0].u.value, arg->uuid, sizeof(arg->uuid));
	msg_arg->params[1].u.value.c = arg->clnt_login;

	rc = tee_session_calc_client_uuid((uuid_t *)&msg_arg->params[1].u.value,
					  arg->clnt_login, arg->clnt_uuid);
	if (rc)
		goto out;

	rc = optee2_to_msg_param(msg_arg->params + 2, arg->num_params, param);
	if (rc)
		goto out;

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess) {
		rc = -ENOMEM;
		goto out;
	}

	if (optee2_do_call_with_arg(ctx, msg_parg)) {
		msg_arg->ret = TEEC_ERROR_COMMUNICATION;
		msg_arg->ret_origin = TEEC_ORIGIN_COMMS;
	}

	if (msg_arg->ret == TEEC_SUCCESS) {
		/* A new session has been created, add it to the list. */
		sess->session_id = msg_arg->session;
		mutex_lock(&ctxdata->mutex);
		list_add(&sess->list_node, &ctxdata->sess_list);
		mutex_unlock(&ctxdata->mutex);
	} else {
		kfree(sess);
	}

	if (optee2_from_msg_param(param, arg->num_params, msg_arg->params + 2)) {
		arg->ret = TEEC_ERROR_COMMUNICATION;
		arg->ret_origin = TEEC_ORIGIN_COMMS;
		/* Close session again to avoid leakage */
		optee2_close_session(ctx, msg_arg->session);
	} else {
		arg->session = msg_arg->session;
		arg->ret = msg_arg->ret;
		arg->ret_origin = msg_arg->ret_origin;
	}
out:
	tee_shm_free(shm);

	return rc;
}

int optee2_close_session(struct tee_context *ctx, u32 session)
{
	struct optee2_context_data *ctxdata = ctx->data;
	struct tee_shm *shm;
	struct optee2_msg_arg *msg_arg;
	phys_addr_t msg_parg;
	struct optee2_session *sess;

	/* Check that the session is valid and remove it from the list */
	mutex_lock(&ctxdata->mutex);
	sess = find_session(ctxdata, session);
	if (sess)
		list_del(&sess->list_node);
	mutex_unlock(&ctxdata->mutex);
	if (!sess)
		return -EINVAL;
	kfree(sess);

	shm = get_msg_arg(ctx, 0, &msg_arg, &msg_parg);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	msg_arg->cmd = OPTEE2_MSG_CMD_CLOSE_SESSION;
	msg_arg->session = session;
	optee2_do_call_with_arg(ctx, msg_parg);

	tee_shm_free(shm);
	return 0;
}

int optee2_invoke_func(struct tee_context *ctx, struct tee_ioctl_invoke_arg *arg,
		      struct tee_param *param)
{
	struct optee2_context_data *ctxdata = ctx->data;
	struct tee_shm *shm;
	struct optee2_msg_arg *msg_arg;
	phys_addr_t msg_parg;
	struct optee2_session *sess;
	int rc;

	/* Check that the session is valid */
	mutex_lock(&ctxdata->mutex);
	sess = find_session(ctxdata, arg->session);
	mutex_unlock(&ctxdata->mutex);
	if (!sess)
		return -EINVAL;

	shm = get_msg_arg(ctx, arg->num_params, &msg_arg, &msg_parg);
	if (IS_ERR(shm))
		return PTR_ERR(shm);
	msg_arg->cmd = OPTEE2_MSG_CMD_INVOKE_COMMAND;
	msg_arg->func = arg->func;
	msg_arg->session = arg->session;
	msg_arg->cancel_id = arg->cancel_id;

	rc = optee2_to_msg_param(msg_arg->params, arg->num_params, param);
	if (rc)
		goto out;

	if (optee2_do_call_with_arg(ctx, msg_parg)) {
		msg_arg->ret = TEEC_ERROR_COMMUNICATION;
		msg_arg->ret_origin = TEEC_ORIGIN_COMMS;
	}

	if (optee2_from_msg_param(param, arg->num_params, msg_arg->params)) {
		msg_arg->ret = TEEC_ERROR_COMMUNICATION;
		msg_arg->ret_origin = TEEC_ORIGIN_COMMS;
	}

	arg->ret = msg_arg->ret;
	arg->ret_origin = msg_arg->ret_origin;
out:
	tee_shm_free(shm);
	return rc;
}

int optee2_cancel_req(struct tee_context *ctx, u32 cancel_id, u32 session)
{
	struct optee2_context_data *ctxdata = ctx->data;
	struct tee_shm *shm;
	struct optee2_msg_arg *msg_arg;
	phys_addr_t msg_parg;
	struct optee2_session *sess;

	/* Check that the session is valid */
	mutex_lock(&ctxdata->mutex);
	sess = find_session(ctxdata, session);
	mutex_unlock(&ctxdata->mutex);
	if (!sess)
		return -EINVAL;

	shm = get_msg_arg(ctx, 0, &msg_arg, &msg_parg);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	msg_arg->cmd = OPTEE2_MSG_CMD_CANCEL;
	msg_arg->session = session;
	msg_arg->cancel_id = cancel_id;
	optee2_do_call_with_arg(ctx, msg_parg);

	tee_shm_free(shm);
	return 0;
}

/**
 * optee2_enable_shm_cache() - Enables caching of some shared memory allocation
 *			      in OP-TEE
 * @optee2:	main service struct
 */
void optee2_enable_shm_cache(struct optee2 *optee2)
{
	struct optee2_call_waiter w;

	/* We need to retry until secure world isn't busy. */
	optee2_cq_wait_init(&optee2->call_queue, &w);
	while (true) {
		optee2_res_t res;

		optee2->invoke_fn(OPTEE2_SMC_ENABLE_SHM_CACHE, 0, 0, 0, 0, 0, 0,
				 0, &res);
		if (res.a0 == OPTEE2_SMC_RETURN_OK)
			break;
		optee2_cq_wait_for_completion(&optee2->call_queue, &w);
	}
	optee2_cq_wait_final(&optee2->call_queue, &w);
}

/**
 * optee2_disable_shm_cache() - Disables caching of some shared memory allocation
 *			      in OP-TEE
 * @optee2:	main service struct
 */
void optee2_disable_shm_cache(struct optee2 *optee2)
{
	struct optee2_call_waiter w;

	/* We need to retry until secure world isn't busy. */
	optee2_cq_wait_init(&optee2->call_queue, &w);
	while (true) {
		union {
			optee2_res_t res;
			struct optee2_smc_disable_shm_cache_result result;
		} res;

		optee2->invoke_fn(OPTEE2_SMC_DISABLE_SHM_CACHE, 0, 0, 0, 0, 0, 0,
				 0, &res.res);
		if (res.result.status == OPTEE2_SMC_RETURN_ENOTAVAIL)
			break; /* All shm's freed */
		if (res.result.status == OPTEE2_SMC_RETURN_OK) {
			struct tee_shm *shm;

			shm = reg_pair_to_ptr(res.result.shm_upper32,
					      res.result.shm_lower32);
			tee_shm_free(shm);
		} else {
			optee2_cq_wait_for_completion(&optee2->call_queue, &w);
		}
	}
	optee2_cq_wait_final(&optee2->call_queue, &w);
}

#define PAGELIST_ENTRIES_PER_PAGE				\
	((OPTEE2_MSG_NONCONTIG_PAGE_SIZE / sizeof(u64)) - 1)

/**
 * optee2_fill_pages_list() - write list of user pages to given shared
 * buffer.
 *
 * @dst: page-aligned buffer where list of pages will be stored
 * @pages: array of pages that represents shared buffer
 * @num_pages: number of entries in @pages
 * @page_offset: offset of user buffer from page start
 *
 * @dst should be big enough to hold list of user page addresses and
 *	links to the next pages of buffer
 */
void optee2_fill_pages_list(u64 *dst, struct page **pages, int num_pages,
			   size_t page_offset)
{
	int n = 0;
	phys_addr_t optee2_page;
	/*
	 * Refer to OPTEE2_MSG_ATTR_NONCONTIG description in optee2_msg.h
	 * for details.
	 */
	struct {
		u64 pages_list[PAGELIST_ENTRIES_PER_PAGE];
		u64 next_page_data;
	} *pages_data;

	/*
	 * Currently OP-TEE uses 4k page size and it does not looks
	 * like this will change in the future.  On other hand, there are
	 * no know ARM architectures with page size < 4k.
	 * Thus the next built assert looks redundant. But the following
	 * code heavily relies on this assumption, so it is better be
	 * safe than sorry.
	 */
	BUILD_BUG_ON(PAGE_SIZE < OPTEE2_MSG_NONCONTIG_PAGE_SIZE);

	pages_data = (void *)dst;
	/*
	 * If linux page is bigger than 4k, and user buffer offset is
	 * larger than 4k/8k/12k/etc this will skip first 4k pages,
	 * because they bear no value data for OP-TEE.
	 */
	optee2_page = page_to_phys(*pages) +
		round_down(page_offset, OPTEE2_MSG_NONCONTIG_PAGE_SIZE);

	while (true) {
		pages_data->pages_list[n++] = optee2_page;

		if (n == PAGELIST_ENTRIES_PER_PAGE) {
			pages_data->next_page_data =
				virt_to_phys(pages_data + 1);
			pages_data++;
			n = 0;
		}

		optee2_page += OPTEE2_MSG_NONCONTIG_PAGE_SIZE;
		if (!(optee2_page & ~PAGE_MASK)) {
			if (!--num_pages)
				break;
			pages++;
			optee2_page = page_to_phys(*pages);
		}
	}
}

/*
 * The final entry in each pagelist page is a pointer to the next
 * pagelist page.
 */
static size_t get_pages_list_size(size_t num_entries)
{
	int pages = DIV_ROUND_UP(num_entries, PAGELIST_ENTRIES_PER_PAGE);

	return pages * OPTEE2_MSG_NONCONTIG_PAGE_SIZE;
}

u64 *optee2_allocate_pages_list(size_t num_entries)
{
	return alloc_pages_exact(get_pages_list_size(num_entries), GFP_KERNEL);
}

void optee2_free_pages_list(void *list, size_t num_entries)
{
	free_pages_exact(list, get_pages_list_size(num_entries));
}

static bool is_normal_memory(pgprot_t p)
{
#if defined(CONFIG_ARM)
	return (((pgprot_val(p) & L_PTE_MT_MASK) == L_PTE_MT_WRITEALLOC) ||
		((pgprot_val(p) & L_PTE_MT_MASK) == L_PTE_MT_WRITEBACK));
#elif defined(CONFIG_ARM64)
	return (pgprot_val(p) & PTE_ATTRINDX_MASK) == PTE_ATTRINDX(MT_NORMAL);
#else
#warning "Unuspported architecture"
	return true; /* TODO */
#endif
}

static int __check_mem_type(struct vm_area_struct *vma, unsigned long end)
{
	while (vma && is_normal_memory(vma->vm_page_prot)) {
		if (vma->vm_end >= end)
			return 0;
		vma = vma->vm_next;
	}

	return -EINVAL;
}

static int check_mem_type(unsigned long start, size_t num_pages)
{
	struct mm_struct *mm = current->mm;
	int rc;

	/*
	 * Allow kernel address to register with OP-TEE as kernel
	 * pages are configured as normal memory only.
	 */
	if (virt_addr_valid(start))
		return 0;

	mmap_read_lock(mm);
	rc = __check_mem_type(find_vma(mm, start),
			      start + num_pages * PAGE_SIZE);
	mmap_read_unlock(mm);

	return rc;
}

int optee2_shm_register(struct tee_context *ctx, struct tee_shm *shm,
		       struct page **pages, size_t num_pages,
		       unsigned long start)
{
	struct tee_shm *shm_arg = NULL;
	struct optee2_msg_arg *msg_arg;
	u64 *pages_list;
	phys_addr_t msg_parg;
	int rc;

	if (!num_pages)
		return -EINVAL;

	rc = check_mem_type(start, num_pages);
	if (rc)
		return rc;

	pages_list = optee2_allocate_pages_list(num_pages);
	if (!pages_list)
		return -ENOMEM;

	shm_arg = get_msg_arg(ctx, 1, &msg_arg, &msg_parg);
	if (IS_ERR(shm_arg)) {
		rc = PTR_ERR(shm_arg);
		goto out;
	}

	optee2_fill_pages_list(pages_list, pages, num_pages,
			      tee_shm_get_page_offset(shm));

	msg_arg->cmd = OPTEE2_MSG_CMD_REGISTER_SHM;
	msg_arg->params->attr = OPTEE2_MSG_ATTR_TYPE_TMEM_OUTPUT |
				OPTEE2_MSG_ATTR_NONCONTIG;
	msg_arg->params->u.tmem.shm_ref = (unsigned long)shm;
	msg_arg->params->u.tmem.size = tee_shm_get_size(shm);
	/*
	 * In the least bits of msg_arg->params->u.tmem.buf_ptr we
	 * store buffer offset from 4k page, as described in OP-TEE ABI.
	 */
	msg_arg->params->u.tmem.buf_ptr = virt_to_phys(pages_list) |
	  (tee_shm_get_page_offset(shm) & (OPTEE2_MSG_NONCONTIG_PAGE_SIZE - 1));

	if (optee2_do_call_with_arg(ctx, msg_parg) ||
	    msg_arg->ret != TEEC_SUCCESS)
		rc = -EINVAL;

	tee_shm_free(shm_arg);
out:
	optee2_free_pages_list(pages_list, num_pages);
	return rc;
}

int optee2_shm_unregister(struct tee_context *ctx, struct tee_shm *shm)
{
	struct tee_shm *shm_arg;
	struct optee2_msg_arg *msg_arg;
	phys_addr_t msg_parg;
	int rc = 0;

	shm_arg = get_msg_arg(ctx, 1, &msg_arg, &msg_parg);
	if (IS_ERR(shm_arg))
		return PTR_ERR(shm_arg);

	msg_arg->cmd = OPTEE2_MSG_CMD_UNREGISTER_SHM;

	msg_arg->params[0].attr = OPTEE2_MSG_ATTR_TYPE_RMEM_INPUT;
	msg_arg->params[0].u.rmem.shm_ref = (unsigned long)shm;

	if (optee2_do_call_with_arg(ctx, msg_parg) ||
	    msg_arg->ret != TEEC_SUCCESS)
		rc = -EINVAL;
	tee_shm_free(shm_arg);
	return rc;
}

int optee2_shm_register_supp(struct tee_context *ctx, struct tee_shm *shm,
			    struct page **pages, size_t num_pages,
			    unsigned long start)
{
	/*
	 * We don't want to register supplicant memory in OP-TEE.
	 * Instead information about it will be passed in RPC code.
	 */
	return check_mem_type(start, num_pages);
}

int optee2_shm_unregister_supp(struct tee_context *ctx, struct tee_shm *shm)
{
	return 0;
}
