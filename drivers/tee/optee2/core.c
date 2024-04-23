// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2015, Linaro Limited
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#if defined(CONFIG_HAVE_ARM_SMCCC)
#include <linux/arm-smccc.h>
#endif
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/tee_drv.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include "optee_private.h"
#if defined(CONFIG_HAVE_ARM_SMCCC)
#include "optee_smc.h"
#elif defined(CONFIG_RISCV_SBI)
#include "optee_sbi.h"
#endif
#include "shm_pool.h"

#if defined(CONFIG_HAVE_ARM_SMCCC)
typedef struct arm_smccc_res optee2_res;
#elif defined(CONFIG_RISCV_SBI)
#endif


#define DRIVER_NAME "optee2"

#define OPTEE2_SHM_NUM_PRIV_PAGES	CONFIG_OPTEE2_SHM_NUM_PRIV_PAGES

/**
 * optee2_from_msg_param() - convert from OPTEE2_MSG parameters to
 *			    struct tee_param
 * @params:	subsystem internal parameter representation
 * @num_params:	number of elements in the parameter arrays
 * @msg_params:	OPTEE2_MSG parameters
 * Returns 0 on success or <0 on failure
 */
int optee2_from_msg_param(struct tee_param *params, size_t num_params,
			 const struct optee2_msg_param *msg_params)
{
	int rc;
	size_t n;
	struct tee_shm *shm;
	phys_addr_t pa;

	for (n = 0; n < num_params; n++) {
		struct tee_param *p = params + n;
		const struct optee2_msg_param *mp = msg_params + n;
		u32 attr = mp->attr & OPTEE2_MSG_ATTR_TYPE_MASK;

		switch (attr) {
		case OPTEE2_MSG_ATTR_TYPE_NONE:
			p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
			memset(&p->u, 0, sizeof(p->u));
			break;
		case OPTEE2_MSG_ATTR_TYPE_VALUE_INPUT:
		case OPTEE2_MSG_ATTR_TYPE_VALUE_OUTPUT:
		case OPTEE2_MSG_ATTR_TYPE_VALUE_INOUT:
			p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT +
				  attr - OPTEE2_MSG_ATTR_TYPE_VALUE_INPUT;
			p->u.value.a = mp->u.value.a;
			p->u.value.b = mp->u.value.b;
			p->u.value.c = mp->u.value.c;
			break;
		case OPTEE2_MSG_ATTR_TYPE_TMEM_INPUT:
		case OPTEE2_MSG_ATTR_TYPE_TMEM_OUTPUT:
		case OPTEE2_MSG_ATTR_TYPE_TMEM_INOUT:
			p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT +
				  attr - OPTEE2_MSG_ATTR_TYPE_TMEM_INPUT;
			p->u.memref.size = mp->u.tmem.size;
			shm = (struct tee_shm *)(unsigned long)
				mp->u.tmem.shm_ref;
			if (!shm) {
				p->u.memref.shm_offs = 0;
				p->u.memref.shm = NULL;
				break;
			}
			rc = tee_shm_get_pa(shm, 0, &pa);
			if (rc)
				return rc;
			p->u.memref.shm_offs = mp->u.tmem.buf_ptr - pa;
			p->u.memref.shm = shm;

			/* Check that the memref is covered by the shm object */
			if (p->u.memref.size) {
				size_t o = p->u.memref.shm_offs +
					   p->u.memref.size - 1;

				rc = tee_shm_get_pa(shm, o, NULL);
				if (rc)
					return rc;
			}
			break;
		case OPTEE2_MSG_ATTR_TYPE_RMEM_INPUT:
		case OPTEE2_MSG_ATTR_TYPE_RMEM_OUTPUT:
		case OPTEE2_MSG_ATTR_TYPE_RMEM_INOUT:
			p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT +
				  attr - OPTEE2_MSG_ATTR_TYPE_RMEM_INPUT;
			p->u.memref.size = mp->u.rmem.size;
			shm = (struct tee_shm *)(unsigned long)
				mp->u.rmem.shm_ref;

			if (!shm) {
				p->u.memref.shm_offs = 0;
				p->u.memref.shm = NULL;
				break;
			}
			p->u.memref.shm_offs = mp->u.rmem.offs;
			p->u.memref.shm = shm;

			break;

		default:
			return -EINVAL;
		}
	}
	return 0;
}

static int to_msg_param_tmp_mem(struct optee2_msg_param *mp,
				const struct tee_param *p)
{
	int rc;
	phys_addr_t pa;

	mp->attr = OPTEE2_MSG_ATTR_TYPE_TMEM_INPUT + p->attr -
		   TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;

	mp->u.tmem.shm_ref = (unsigned long)p->u.memref.shm;
	mp->u.tmem.size = p->u.memref.size;

	if (!p->u.memref.shm) {
		mp->u.tmem.buf_ptr = 0;
		return 0;
	}

	rc = tee_shm_get_pa(p->u.memref.shm, p->u.memref.shm_offs, &pa);
	if (rc)
		return rc;

	mp->u.tmem.buf_ptr = pa;
	mp->attr |= OPTEE2_MSG_ATTR_CACHE_PREDEFINED <<
		    OPTEE2_MSG_ATTR_CACHE_SHIFT;

	return 0;
}

static int to_msg_param_reg_mem(struct optee2_msg_param *mp,
				const struct tee_param *p)
{
	mp->attr = OPTEE2_MSG_ATTR_TYPE_RMEM_INPUT + p->attr -
		   TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;

	mp->u.rmem.shm_ref = (unsigned long)p->u.memref.shm;
	mp->u.rmem.size = p->u.memref.size;
	mp->u.rmem.offs = p->u.memref.shm_offs;
	return 0;
}

/**
 * optee2_to_msg_param() - convert from struct tee_params to OPTEE2_MSG parameters
 * @msg_params:	OPTEE2_MSG parameters
 * @num_params:	number of elements in the parameter arrays
 * @params:	subsystem itnernal parameter representation
 * Returns 0 on success or <0 on failure
 */
int optee2_to_msg_param(struct optee2_msg_param *msg_params, size_t num_params,
		       const struct tee_param *params)
{
	int rc;
	size_t n;

	for (n = 0; n < num_params; n++) {
		const struct tee_param *p = params + n;
		struct optee2_msg_param *mp = msg_params + n;

		switch (p->attr) {
		case TEE_IOCTL_PARAM_ATTR_TYPE_NONE:
			mp->attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
			memset(&mp->u, 0, sizeof(mp->u));
			break;
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT:
			mp->attr = OPTEE2_MSG_ATTR_TYPE_VALUE_INPUT + p->attr -
				   TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
			mp->u.value.a = p->u.value.a;
			mp->u.value.b = p->u.value.b;
			mp->u.value.c = p->u.value.c;
			break;
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
			if (tee_shm_is_registered(p->u.memref.shm))
				rc = to_msg_param_reg_mem(mp, p);
			else
				rc = to_msg_param_tmp_mem(mp, p);
			if (rc)
				return rc;
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

static void optee2_get_version(struct tee_device *teedev,
			      struct tee_ioctl_version_data *vers)
{
	struct tee_ioctl_version_data v = {
		.impl_id = TEE_IMPL_ID_OPTEE2,
		.impl_caps = TEE_OPTEE_CAP_TZ,
		.gen_caps = TEE_GEN_CAP_GP,
	};
	struct optee2 *optee2 = tee_get_drvdata(teedev);

	if (optee2->sec_caps & OPTEE2_SMC_SEC_CAP_DYNAMIC_SHM)
		v.gen_caps |= TEE_GEN_CAP_REG_MEM;
	if (optee2->sec_caps & OPTEE2_SMC_SEC_CAP_MEMREF_NULL)
		v.gen_caps |= TEE_GEN_CAP_MEMREF_NULL;
	*vers = v;
}

static void optee2_bus_scan(struct work_struct *work)
{
	WARN_ON(optee2_enumerate_devices(PTA_CMD_GET_DEVICES_SUPP));
}

static int optee2_open(struct tee_context *ctx)
{
	struct optee2_context_data *ctxdata;
	struct tee_device *teedev = ctx->teedev;
	struct optee2 *optee2 = tee_get_drvdata(teedev);

	ctxdata = kzalloc(sizeof(*ctxdata), GFP_KERNEL);
	if (!ctxdata)
		return -ENOMEM;

	if (teedev == optee2->supp_teedev) {
		bool busy = true;

		mutex_lock(&optee2->supp.mutex);
		if (!optee2->supp.ctx) {
			busy = false;
			optee2->supp.ctx = ctx;
		}
		mutex_unlock(&optee2->supp.mutex);
		if (busy) {
			kfree(ctxdata);
			return -EBUSY;
		}

		if (!optee2->scan_bus_done) {
			INIT_WORK(&optee2->scan_bus_work, optee2_bus_scan);
			optee2->scan_bus_wq = create_workqueue("optee2_bus_scan");
			if (!optee2->scan_bus_wq) {
				kfree(ctxdata);
				return -ECHILD;
			}
			queue_work(optee2->scan_bus_wq, &optee2->scan_bus_work);
			optee2->scan_bus_done = true;
		}
	}
	mutex_init(&ctxdata->mutex);
	INIT_LIST_HEAD(&ctxdata->sess_list);

	if (optee2->sec_caps & OPTEE2_SMC_SEC_CAP_MEMREF_NULL)
		ctx->cap_memref_null  = true;
	else
		ctx->cap_memref_null = false;

	ctx->data = ctxdata;
	return 0;
}

static void optee2_release(struct tee_context *ctx)
{
	struct optee2_context_data *ctxdata = ctx->data;
	struct tee_device *teedev = ctx->teedev;
	struct optee2 *optee2 = tee_get_drvdata(teedev);
	struct tee_shm *shm;
	struct optee2_msg_arg *arg = NULL;
	phys_addr_t parg;
	struct optee2_session *sess;
	struct optee2_session *sess_tmp;

	if (!ctxdata)
		return;

	shm = tee_shm_alloc(ctx, sizeof(struct optee2_msg_arg), TEE_SHM_MAPPED);
	if (!IS_ERR(shm)) {
		arg = tee_shm_get_va(shm, 0);
		/*
		 * If va2pa fails for some reason, we can't call into
		 * secure world, only free the memory. Secure OS will leak
		 * sessions and finally refuse more sessions, but we will
		 * at least let normal world reclaim its memory.
		 */
		if (!IS_ERR(arg))
			if (tee_shm_va2pa(shm, arg, &parg))
				arg = NULL; /* prevent usage of parg below */
	}

	list_for_each_entry_safe(sess, sess_tmp, &ctxdata->sess_list,
				 list_node) {
		list_del(&sess->list_node);
		if (!IS_ERR_OR_NULL(arg)) {
			memset(arg, 0, sizeof(*arg));
			arg->cmd = OPTEE2_MSG_CMD_CLOSE_SESSION;
			arg->session = sess->session_id;
			optee2_do_call_with_arg(ctx, parg);
		}
		kfree(sess);
	}
	kfree(ctxdata);

	if (!IS_ERR(shm))
		tee_shm_free(shm);

	ctx->data = NULL;

	if (teedev == optee2->supp_teedev) {
		if (optee2->scan_bus_wq) {
			destroy_workqueue(optee2->scan_bus_wq);
			optee2->scan_bus_wq = NULL;
		}
		optee2_supp_release(&optee2->supp);
	}
}

static const struct tee_driver_ops optee2_ops = {
	.get_version = optee2_get_version,
	.open = optee2_open,
	.release = optee2_release,
	.open_session = optee2_open_session,
	.close_session = optee2_close_session,
	.invoke_func = optee2_invoke_func,
	.cancel_req = optee2_cancel_req,
	.shm_register = optee2_shm_register,
	.shm_unregister = optee2_shm_unregister,
};

static const struct tee_desc optee2_desc = {
	.name = DRIVER_NAME "-clnt",
	.ops = &optee2_ops,
	.owner = THIS_MODULE,
};

static const struct tee_driver_ops optee2_supp_ops = {
	.get_version = optee2_get_version,
	.open = optee2_open,
	.release = optee2_release,
	.supp_recv = optee2_supp_recv,
	.supp_send = optee2_supp_send,
	.shm_register = optee2_shm_register_supp,
	.shm_unregister = optee2_shm_unregister_supp,
};

static const struct tee_desc optee2_supp_desc = {
	.name = DRIVER_NAME "-supp",
	.ops = &optee2_supp_ops,
	.owner = THIS_MODULE,
	.flags = TEE_DESC_PRIVILEGED,
};

static bool optee2_msg_api_uid_is_optee2_api(optee2_invoke_fn *invoke_fn)
{
	optee2_res_t res;

	invoke_fn(OPTEE2_SMC_CALLS_UID, 0, 0, 0, 0, 0, 0, 0, &res);

	if (res.a0 == OPTEE2_MSG_UID_0 && res.a1 == OPTEE2_MSG_UID_1 &&
	    res.a2 == OPTEE2_MSG_UID_2 && res.a3 == OPTEE2_MSG_UID_3)
		return true;
	return true;
}

static void optee2_msg_get_os_revision(optee2_invoke_fn *invoke_fn)
{
	union {
		optee2_res_t res;
		struct optee2_smc_call_get_os_revision_result result;
	} res = {
		.result = {
			.build_id = 0
		}
	};

	invoke_fn(OPTEE2_SMC_CALL_GET_OS_REVISION, 0, 0, 0, 0, 0, 0, 0,
		  &res.res);

	if (res.result.build_id)
		pr_info("revision2 %lu.%lu (%08lx)", res.result.major,
			res.result.minor, res.result.build_id);
	else
		pr_info("revision2 %lu.%lu", res.result.major, res.result.minor);
}

static bool optee2_msg_api_revision_is_compatible(optee2_invoke_fn *invoke_fn)
{
	union {
		optee2_res_t res;
		struct optee2_smc_calls_revision_result result;
	} res;

	invoke_fn(OPTEE2_SMC_CALLS_REVISION, 0, 0, 0, 0, 0, 0, 0, &res.res);

	if (res.result.major == OPTEE2_MSG_REVISION_MAJOR &&
	    (int)res.result.minor >= OPTEE2_MSG_REVISION_MINOR)
		return true;
	return false;
}

static bool optee2_msg_exchange_capabilities(optee2_invoke_fn *invoke_fn,
					    u32 *sec_caps)
{
	union {
		optee2_res_t res;
		struct optee2_smc_exchange_capabilities_result result;
	} res;
	u32 a1 = 0;

	/*
	 * TODO This isn't enough to tell if it's UP system (from kernel
	 * point of view) or not, is_smp() returns the the information
	 * needed, but can't be called directly from here.
	 */
	if (!IS_ENABLED(CONFIG_SMP) || nr_cpu_ids == 1)
		a1 |= OPTEE2_SMC_NSEC_CAP_UNIPROCESSOR;

	invoke_fn(OPTEE2_SMC_EXCHANGE_CAPABILITIES, a1, 0, 0, 0, 0, 0, 0,
		  &res.res);

	if (res.result.status != OPTEE2_SMC_RETURN_OK)
		return false;
	*sec_caps = res.result.capabilities;
	return true;
}

static struct tee_shm_pool *optee2_config_dyn_shm(void)
{
	struct tee_shm_pool_mgr *priv_mgr;
	struct tee_shm_pool_mgr *dmabuf_mgr;
	void *rc;

	rc = optee2_shm_pool_alloc_pages();
	if (IS_ERR(rc))
		return rc;
	priv_mgr = rc;

	rc = optee2_shm_pool_alloc_pages();
	if (IS_ERR(rc)) {
		tee_shm_pool_mgr_destroy(priv_mgr);
		return rc;
	}
	dmabuf_mgr = rc;

	rc = tee_shm_pool_alloc(priv_mgr, dmabuf_mgr);
	if (IS_ERR(rc)) {
		tee_shm_pool_mgr_destroy(priv_mgr);
		tee_shm_pool_mgr_destroy(dmabuf_mgr);
	}

	return rc;
}

static struct tee_shm_pool *
optee2_config_shm_memremap(optee2_invoke_fn *invoke_fn, void **memremaped_shm)
{
	union {
		optee2_res_t res;
		struct optee2_smc_get_shm_config_result result;
	} res;
	unsigned long vaddr;
	phys_addr_t paddr;
	size_t size;
	phys_addr_t begin;
	phys_addr_t end;
	void *va;
	struct tee_shm_pool_mgr *priv_mgr;
	struct tee_shm_pool_mgr *dmabuf_mgr;
	void *rc;
	const int sz = OPTEE2_SHM_NUM_PRIV_PAGES * PAGE_SIZE;

	invoke_fn(OPTEE2_SMC_GET_SHM_CONFIG, 0, 0, 0, 0, 0, 0, 0, &res.res);
	if (res.result.status != OPTEE2_SMC_RETURN_OK) {
		pr_err("static2 shm service not available\n");
		return ERR_PTR(-ENOENT);
	}

	if (res.result.settings != OPTEE2_SMC_SHM_CACHED) {
		pr_err("only2 normal cached shared memory supported\n");
		return ERR_PTR(-EINVAL);
	}

	begin = roundup(res.result.start, PAGE_SIZE);
	end = rounddown(res.result.start + res.result.size, PAGE_SIZE);
	paddr = begin;
	size = end - begin;

	printk("OPTEE2: Start 0x%lx, size 0x%lx\n", paddr, size);

	if (size < 2 * OPTEE2_SHM_NUM_PRIV_PAGES * PAGE_SIZE) {
		pr_err("too small shared memory area\n");
		return ERR_PTR(-EINVAL);
	}

	va = memremap(paddr, size, MEMREMAP_WB);
	if (!va) {
		pr_err("shared memory ioremap failed\n");
		return ERR_PTR(-EINVAL);
	}
	vaddr = (unsigned long)va;

	rc = tee_shm_pool_mgr_alloc_res_mem(vaddr, paddr, sz,
					    3 /* 8 bytes aligned */);
	if (IS_ERR(rc))
		goto err_memunmap;
	priv_mgr = rc;

	vaddr += sz;
	paddr += sz;
	size -= sz;

	rc = tee_shm_pool_mgr_alloc_res_mem(vaddr, paddr, size, PAGE_SHIFT);
	if (IS_ERR(rc))
		goto err_free_priv_mgr;
	dmabuf_mgr = rc;

	rc = tee_shm_pool_alloc(priv_mgr, dmabuf_mgr);
	if (IS_ERR(rc))
		goto err_free_dmabuf_mgr;

	*memremaped_shm = va;

	return rc;

err_free_dmabuf_mgr:
	tee_shm_pool_mgr_destroy(dmabuf_mgr);
err_free_priv_mgr:
	tee_shm_pool_mgr_destroy(priv_mgr);
err_memunmap:
	memunmap(va);
	return rc;
}

#if defined(CONFIG_HAVE_ARM_SMCCC)
/* Simple wrapper functions to be able to use a function pointer */
static void optee2_smccc_smc(unsigned long a0, unsigned long a1,
			    unsigned long a2, unsigned long a3,
			    unsigned long a4, unsigned long a5,
			    unsigned long a6, unsigned long a7,
			    optee2_res_t *res)
{
	/* unsigned long val; */
	/* asm volatile ("mrs %0, CNTVCT_EL0": "=r"(val)); */
	arm_smccc_smc(a0, a1, a2, a3, a4, a5, a6, a7, res);
	/* printk("before  %lu\n", val); */
}

static void optee2_smccc_hvc(unsigned long a0, unsigned long a1,
			    unsigned long a2, unsigned long a3,
			    unsigned long a4, unsigned long a5,
			    unsigned long a6, unsigned long a7,
			    optee2_res_t *res)
{
	arm_smccc_hvc(a0, a1, a2, a3, a4, a5, a6, a7, res);
}

#elif defined(CONFIG_RISCV_SBI)

static void sbi_ecall(unsigned long ext, unsigned long fid, 
			unsigned long arg0, unsigned long arg1, 
			unsigned long arg2, unsigned long arg3, 
			unsigned long arg4, unsigned long arg5,
			optee2_res_t *res) {
	register unsigned long a0 asm("a0") = (unsigned long)arg0;
	register unsigned long a1 asm("a1") = (unsigned long)arg1;
	register unsigned long a2 asm("a2") = (unsigned long)arg2;
	register unsigned long a3 asm("a3") = (unsigned long)arg3;
	register unsigned long a4 asm("a4") = (unsigned long)arg4;
	register unsigned long a5 asm("a5") = (unsigned long)arg5;
	register unsigned long a6 asm("a6") = (unsigned long)fid;
	register unsigned long a7 asm("a7") = (unsigned long)ext;
	asm volatile ("ecall"
		: "+r" (a0), "+r" (a1), "+r" (a2), "+r" (a3)
		: "r" (a4), "r" (a5), "r"(a6), "r"(a7)
		: "memory");
	res->a0 = a0;
	res->a1 = a1;
	res->a2 = a2;
	res->a3 = a3;
}

static void optee2_smccc_sbi(unsigned long a0, unsigned long a1,
			    unsigned long a2, unsigned long a3,
			    unsigned long a4, unsigned long a5,
			    unsigned long a6, unsigned long a7,
			    optee2_res_t *res)
{
	/* unsigned long val; */
	/* asm volatile ("rdtime %0": "=r"(val)); */
	sbi_ecall(SBI_EXTID_TEE, a0, a0, a1, a2, a3, a4, a5, res);
	/* printk("before  %lu\n", val); */
}

#endif

static optee2_invoke_fn *get_invoke_func(struct device *dev)
{
	const char *method;

	pr_info("probing for conduit method.\n");

	if (device_property_read_string(dev, "method", &method)) {
		pr_warn("missing \"method\" property\n");
		return ERR_PTR(-ENXIO);
	}

#if defined(CONFIG_HAVE_ARM_SMCCC)
	if (!strcmp("hvc", method))
		return optee2_smccc_hvc;
	else if (!strcmp("smc", method))
		return optee2_smccc_smc;
#endif
#ifdef CONFIG_RISCV_SBI
	else if (!strcmp("sbi", method)){
		printk("using sbi smc call");
		return optee2_smccc_sbi;
	}
#endif

	pr_warn("invalid \"method\" property: %s\n", method);
	return ERR_PTR(-EINVAL);
}

static int optee2_remove(struct platform_device *pdev)
{
	struct optee2 *optee2 = platform_get_drvdata(pdev);

	/*
	 * Ask OP-TEE to free all cached shared memory objects to decrease
	 * reference counters and also avoid wild pointers in secure world
	 * into the old shared memory range.
	 */
	optee2_disable_shm_cache(optee2);

	/*
	 * The two devices have to be unregistered before we can free the
	 * other resources.
	 */
	tee_device_unregister(optee2->supp_teedev);
	tee_device_unregister(optee2->teedev);

	tee_shm_pool_free(optee2->pool);
	if (optee2->memremaped_shm)
		memunmap(optee2->memremaped_shm);
	optee2_wait_queue_exit(&optee2->wait_queue);
	optee2_supp_uninit(&optee2->supp);
	mutex_destroy(&optee2->call_queue.mutex);

	kfree(optee2);

	return 0;
}

static int optee2_probe(struct platform_device *pdev)
{
	optee2_invoke_fn *invoke_fn;
	struct tee_shm_pool *pool = ERR_PTR(-EINVAL);
	struct optee2 *optee2 = NULL;
	void *memremaped_shm = NULL;
	struct tee_device *teedev;
	u32 sec_caps;
	int rc;

	pr_info("CROSSCON optee2: %s\n", pdev->name);

	invoke_fn = get_invoke_func(&pdev->dev);
	if (IS_ERR(invoke_fn))
		return PTR_ERR(invoke_fn);

	if (!optee2_msg_api_uid_is_optee2_api(invoke_fn)) {
		pr_warn("api uid mismatch\n");
		return -EINVAL;
	}

	optee2_msg_get_os_revision(invoke_fn);

	if (!optee2_msg_api_revision_is_compatible(invoke_fn)) {
		pr_warn("api revision mismatch\n");
		return -EINVAL;
	}

	if (!optee2_msg_exchange_capabilities(invoke_fn, &sec_caps)) {
		pr_warn("capabilities mismatch\n");
		return -EINVAL;
	}

	/*
	 * Try to use dynamic shared memory if possible
	 */
	if (sec_caps & OPTEE2_SMC_SEC_CAP_DYNAMIC_SHM)
		pool = optee2_config_dyn_shm();

	/*
	 * If dynamic shared memory is not available or failed - try static one
	 */
	if (IS_ERR(pool) && (sec_caps & OPTEE2_SMC_SEC_CAP_HAVE_RESERVED_SHM))
		pool = optee2_config_shm_memremap(invoke_fn, &memremaped_shm);

	if (IS_ERR(pool))
		return PTR_ERR(pool);

	optee2 = kzalloc(sizeof(*optee2), GFP_KERNEL);
	if (!optee2) {
		rc = -ENOMEM;
		goto err;
	}

	optee2->invoke_fn = invoke_fn;
	optee2->sec_caps = sec_caps;

	teedev = tee_device_alloc(&optee2_desc, NULL, pool, optee2);
	if (IS_ERR(teedev)) {
		rc = PTR_ERR(teedev);
		goto err;
	}
	optee2->teedev = teedev;

	teedev = tee_device_alloc(&optee2_supp_desc, NULL, pool, optee2);
	if (IS_ERR(teedev)) {
		rc = PTR_ERR(teedev);
		goto err;
	}
	optee2->supp_teedev = teedev;

	rc = tee_device_register(optee2->teedev);
	if (rc)
		goto err;

	rc = tee_device_register(optee2->supp_teedev);
	if (rc)
		goto err;

	mutex_init(&optee2->call_queue.mutex);
	INIT_LIST_HEAD(&optee2->call_queue.waiters);
	optee2_wait_queue_init(&optee2->wait_queue);
	optee2_supp_init(&optee2->supp);
	optee2->memremaped_shm = memremaped_shm;
	optee2->pool = pool;

	optee2_enable_shm_cache(optee2);

	if (optee2->sec_caps & OPTEE2_SMC_SEC_CAP_DYNAMIC_SHM)
		pr_info("dynamic shared memory is enabled\n");

	platform_set_drvdata(pdev, optee2);

	rc = optee2_enumerate_devices(PTA_CMD_GET_DEVICES);
	if (rc) {
		optee2_remove(pdev);
		return rc;
	}

	pr_info("initialized driver\n");
	return 0;
err:
	if (optee2) {
		/*
		 * tee_device_unregister() is safe to call even if the
		 * devices hasn't been registered with
		 * tee_device_register() yet.
		 */
		tee_device_unregister(optee2->supp_teedev);
		tee_device_unregister(optee2->teedev);
		kfree(optee2);
	}
	if (pool)
		tee_shm_pool_free(pool);
	if (memremaped_shm)
		memunmap(memremaped_shm);
	return rc;
}

static const struct of_device_id optee2_dt_match[] = {
	{ .compatible = "crosscon,optee2-tz" },
	{},
};
MODULE_DEVICE_TABLE(of, optee2_dt_match);

static struct platform_driver optee2_driver = {
	.probe  = optee2_probe,
	.remove = optee2_remove,
	.driver = {
		.name = "optee2",
		.of_match_table = optee2_dt_match,
	},
};
module_platform_driver(optee2_driver);


MODULE_AUTHOR("CROSSCON");
MODULE_DESCRIPTION("OP-TEE2 driver");
MODULE_SUPPORTED_DEVICE("");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:optee2");
