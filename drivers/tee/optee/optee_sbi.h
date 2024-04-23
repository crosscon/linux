/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
/*
 * Copyright (c) 2015-2019, Linaro Limited
 */
#ifndef OPTEE_SBI_H
#define OPTEE_SBI_H

// #include <linux/riscv-sbicc.h>
#include <linux/bitops.h>


#define SBI_EXTID_TEE (0x544545)

#if defined(CONFIG_HAVE_RISCV_SBI)
typedef struct arm_smccc_res optee_res;
#elif defined(CONFIG_RISCV_SBI)
/**
 * optee_res_t - Result from SMC/HVC call
 * @a0-a3 result values from registers 0 to 3
 */
struct sbiret {
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
};

typedef struct sbiret optee_res_t;

#endif

#define RISCV_SBI_STD_CALL	        (0UL)
#define RISCV_SBI_FAST_CALL	        (1UL)
#define RISCV_SBI_TYPE_SHIFT		31

#define RISCV_SBI_SMC_32		0
#define RISCV_SBI_SMC_64		1
#define RISCV_SBI_CALL_CONV_SHIFT	30

#define RISCV_SBI_OWNER_MASK		0x3F
#define RISCV_SBI_OWNER_SHIFT		24

#define RISCV_SBI_FUNC_MASK		0xFFFF

#define RISCV_SBI_IS_FAST_CALL(smc_val)	\
	((smc_val) & (RISCV_SBI_FAST_CALL << RISCV_SBI_TYPE_SHIFT))
#define RISCV_SBI_IS_64(smc_val) \
	((smc_val) & (RISCV_SBI_SMC_64 << RISCV_SBI_CALL_CONV_SHIFT))
#define RISCV_SBI_FUNC_NUM(smc_val)	((smc_val) & RISCV_SBI_FUNC_MASK)
#define RISCV_SBI_OWNER_NUM(smc_val) \
	(((smc_val) >> RISCV_SBI_OWNER_SHIFT) & RISCV_SBI_OWNER_MASK)

#define RISCV_SBI_CALL_VAL(type, calling_convention, owner, func_num) \
	(((type) << RISCV_SBI_TYPE_SHIFT) | \
	((calling_convention) << RISCV_SBI_CALL_CONV_SHIFT) | \
	(((owner) & RISCV_SBI_OWNER_MASK) << RISCV_SBI_OWNER_SHIFT) | \
	((func_num) & RISCV_SBI_FUNC_MASK))

#define RISCV_SBI_OWNER_ARCH		0
#define RISCV_SBI_OWNER_CPU		1
#define RISCV_SBI_OWNER_SIP		2
#define RISCV_SBI_OWNER_OEM		3
#define RISCV_SBI_OWNER_STANDARD	4
#define RISCV_SBI_OWNER_STANDARD_HYP	5
#define RISCV_SBI_OWNER_VENDOR_HYP	6
#define RISCV_SBI_OWNER_TRUSTED_APP	48
#define RISCV_SBI_OWNER_TRUSTED_APP_END	49
#define RISCV_SBI_OWNER_TRUSTED_OS	50
#define RISCV_SBI_OWNER_TRUSTED_OS_END	63

#define RISCV_SBI_QUIRK_NONE		0
#define RISCV_SBI_QUIRK_QCOM_A6		1 /* Save/restore register a6 */

#define RISCV_SBI_VERSION_1_0		0x10000
#define RISCV_SBI_VERSION_1_1		0x10001
#define RISCV_SBI_VERSION_1_2		0x10002

#define OPTEE_SMC_STD_CALL_VAL(func_num) \
	RISCV_SBI_CALL_VAL(RISCV_SBI_STD_CALL, RISCV_SBI_SMC_32, \
			   RISCV_SBI_OWNER_TRUSTED_OS, (func_num))
#define OPTEE_SMC_FAST_CALL_VAL(func_num) \
	RISCV_SBI_CALL_VAL(RISCV_SBI_FAST_CALL, RISCV_SBI_SMC_32, \
			   RISCV_SBI_OWNER_TRUSTED_OS, (func_num))

/*
 * Function specified by SMC Calling convention.
 */
#define OPTEE_SMC_FUNCID_CALLS_COUNT	0xFF00
#define OPTEE_SMC_CALLS_COUNT \
	RISCV_SBI_CALL_VAL(OPTEE_SMC_FAST_CALL, SMCCC_SMC_32, \
			   SMCCC_OWNER_TRUSTED_OS_END, \
			   OPTEE_SMC_FUNCID_CALLS_COUNT)

/*
 * Normal cached memory (write-back), shareable for SMP systems and not
 * shareable for UP systems.
 */
#define OPTEE_SMC_SHM_CACHED		1

/*
 * a0..a7 is used as register names in the descriptions below, on arm32
 * that translates to r0..r7 and on arm64 to w0..w7. In both cases it's
 * 32-bit registers.
 */

/*
 * Function specified by SMC Calling convention
 *
 * Return one of the following UIDs if using API specified in this file
 * without further extentions:
 * 65cb6b93-af0c-4617-8ed6-644a8d1140f8
 * see also OPTEE_SMC_UID_* in optee_msg.h
 */
#define OPTEE_SMC_FUNCID_CALLS_UID OPTEE_MSG_FUNCID_CALLS_UID
#define OPTEE_SMC_CALLS_UID \
	RISCV_SBI_CALL_VAL(RISCV_SBI_FAST_CALL, RISCV_SBI_SMC_32, \
			   RISCV_SBI_OWNER_TRUSTED_OS_END, \
			   OPTEE_SMC_FUNCID_CALLS_UID)

/*
 * Function specified by SMC Calling convention
 *
 * Returns 2.0 if using API specified in this file without further extentions.
 * see also OPTEE_MSG_REVISION_* in optee_msg.h
 */
#define OPTEE_SMC_FUNCID_CALLS_REVISION OPTEE_MSG_FUNCID_CALLS_REVISION
#define OPTEE_SMC_CALLS_REVISION \
	RISCV_SBI_CALL_VAL(RISCV_SBI_FAST_CALL, RISCV_SBI_SMC_32, \
			   RISCV_SBI_OWNER_TRUSTED_OS_END, \
			   OPTEE_SMC_FUNCID_CALLS_REVISION)

struct optee_smc_calls_revision_result {
	unsigned long major;
	unsigned long minor;
	unsigned long reserved0;
	unsigned long reserved1;
};

/*
 * Get UUID of Trusted OS.
 *
 * Used by non-secure world to figure out which Trusted OS is installed.
 * Note that returned UUID is the UUID of the Trusted OS, not of the API.
 *
 * Returns UUID in a0-4 in the same way as OPTEE_SMC_CALLS_UID
 * described above.
 */
#define OPTEE_SMC_FUNCID_GET_OS_UUID OPTEE_MSG_FUNCID_GET_OS_UUID
#define OPTEE_SMC_CALL_GET_OS_UUID \
	OPTEE_SMC_FAST_CALL_VAL(OPTEE_SMC_FUNCID_GET_OS_UUID)

/*
 * Get revision of Trusted OS.
 *
 * Used by non-secure world to figure out which version of the Trusted OS
 * is installed. Note that the returned revision is the revision of the
 * Trusted OS, not of the API.
 *
 * Returns revision in a0-1 in the same way as OPTEE_SMC_CALLS_REVISION
 * described above. May optionally return a 32-bit build identifier in a2,
 * with zero meaning unspecified.
 */
#define OPTEE_SMC_FUNCID_GET_OS_REVISION OPTEE_MSG_FUNCID_GET_OS_REVISION
#define OPTEE_SMC_CALL_GET_OS_REVISION \
	OPTEE_SMC_FAST_CALL_VAL(OPTEE_SMC_FUNCID_GET_OS_REVISION)

struct optee_smc_call_get_os_revision_result {
	unsigned long major;
	unsigned long minor;
	unsigned long build_id;
	unsigned long reserved1;
};

/*
 * Call with struct optee_msg_arg as argument
 *
 * Call register usage:
 * a0	SMC Function ID, OPTEE_SMC*CALL_WITH_ARG
 * a1	Upper 32bit of a 64bit physical pointer to a struct optee_msg_arg
 * a2	Lower 32bit of a 64bit physical pointer to a struct optee_msg_arg
 * a3	Cache settings, not used if physical pointer is in a predefined shared
 *	memory area else per OPTEE_SMC_SHM_*
 * a4-6	Not used
 * a7	Hypervisor Client ID register
 *
 * Normal return register usage:
 * a0	Return value, OPTEE_SMC_RETURN_*
 * a1-3	Not used
 * a4-7	Preserved
 *
 * OPTEE_SMC_RETURN_ETHREAD_LIMIT return register usage:
 * a0	Return value, OPTEE_SMC_RETURN_ETHREAD_LIMIT
 * a1-3	Preserved
 * a4-7	Preserved
 *
 * RPC return register usage:
 * a0	Return value, OPTEE_SMC_RETURN_IS_RPC(val)
 * a1-2	RPC parameters
 * a3-7	Resume information, must be preserved
 *
 * Possible return values:
 * OPTEE_SMC_RETURN_UNKNOWN_FUNCTION	Trusted OS does not recognize this
 *					function.
 * OPTEE_SMC_RETURN_OK			Call completed, result updated in
 *					the previously supplied struct
 *					optee_msg_arg.
 * OPTEE_SMC_RETURN_ETHREAD_LIMIT	Number of Trusted OS threads exceeded,
 *					try again later.
 * OPTEE_SMC_RETURN_EBADADDR		Bad physcial pointer to struct
 *					optee_msg_arg.
 * OPTEE_SMC_RETURN_EBADCMD		Bad/unknown cmd in struct optee_msg_arg
 * OPTEE_SMC_RETURN_IS_RPC()		Call suspended by RPC call to normal
 *					world.
 */
#define OPTEE_SMC_FUNCID_CALL_WITH_ARG OPTEE_MSG_FUNCID_CALL_WITH_ARG
#define OPTEE_SMC_CALL_WITH_ARG \
	OPTEE_SMC_STD_CALL_VAL(OPTEE_SMC_FUNCID_CALL_WITH_ARG)

/*
 * Get Shared Memory Config
 *
 * Returns the Secure/Non-secure shared memory config.
 *
 * Call register usage:
 * a0	SMC Function ID, OPTEE_SMC_GET_SHM_CONFIG
 * a1-6	Not used
 * a7	Hypervisor Client ID register
 *
 * Have config return register usage:
 * a0	OPTEE_SMC_RETURN_OK
 * a1	Physical address of start of SHM
 * a2	Size of of SHM
 * a3	Cache settings of memory, as defined by the
 *	OPTEE_SMC_SHM_* values above
 * a4-7	Preserved
 *
 * Not available register usage:
 * a0	OPTEE_SMC_RETURN_ENOTAVAIL
 * a1-3 Not used
 * a4-7	Preserved
 */
#define OPTEE_SMC_FUNCID_GET_SHM_CONFIG	7
#define OPTEE_SMC_GET_SHM_CONFIG \
	OPTEE_SMC_FAST_CALL_VAL(OPTEE_SMC_FUNCID_GET_SHM_CONFIG)

struct optee_smc_get_shm_config_result {
	unsigned long status;
	unsigned long start;
	unsigned long size;
	unsigned long settings;
};

/*
 * Exchanges capabilities between normal world and secure world
 *
 * Call register usage:
 * a0	SMC Function ID, OPTEE_SMC_EXCHANGE_CAPABILITIES
 * a1	bitfield of normal world capabilities OPTEE_SMC_NSEC_CAP_*
 * a2-6	Not used
 * a7	Hypervisor Client ID register
 *
 * Normal return register usage:
 * a0	OPTEE_SMC_RETURN_OK
 * a1	bitfield of secure world capabilities OPTEE_SMC_SEC_CAP_*
 * a2-7	Preserved
 *
 * Error return register usage:
 * a0	OPTEE_SMC_RETURN_ENOTAVAIL, can't use the capabilities from normal world
 * a1	bitfield of secure world capabilities OPTEE_SMC_SEC_CAP_*
 * a2-7 Preserved
 */
/* Normal world works as a uniprocessor system */
#define OPTEE_SMC_NSEC_CAP_UNIPROCESSOR		BIT(0)
/* Secure world has reserved shared memory for normal world to use */
#define OPTEE_SMC_SEC_CAP_HAVE_RESERVED_SHM	BIT(0)
/* Secure world can communicate via previously unregistered shared memory */
#define OPTEE_SMC_SEC_CAP_UNREGISTERED_SHM	BIT(1)

/*
 * Secure world supports commands "register/unregister shared memory",
 * secure world accepts command buffers located in any parts of non-secure RAM
 */
#define OPTEE_SMC_SEC_CAP_DYNAMIC_SHM		BIT(2)

/* Secure world supports Shared Memory with a NULL buffer reference */
#define OPTEE_SMC_SEC_CAP_MEMREF_NULL		BIT(4)

#define OPTEE_SMC_FUNCID_EXCHANGE_CAPABILITIES	9
#define OPTEE_SMC_EXCHANGE_CAPABILITIES \
	OPTEE_SMC_FAST_CALL_VAL(OPTEE_SMC_FUNCID_EXCHANGE_CAPABILITIES)

struct optee_smc_exchange_capabilities_result {
	unsigned long status;
	unsigned long capabilities;
	unsigned long reserved0;
	unsigned long reserved1;
};

/*
 * Disable and empties cache of shared memory objects
 *
 * Secure world can cache frequently used shared memory objects, for
 * example objects used as RPC arguments. When secure world is idle this
 * function returns one shared memory reference to free. To disable the
 * cache and free all cached objects this function has to be called until
 * it returns OPTEE_SMC_RETURN_ENOTAVAIL.
 *
 * Call register usage:
 * a0	SMC Function ID, OPTEE_SMC_DISABLE_SHM_CACHE
 * a1-6	Not used
 * a7	Hypervisor Client ID register
 *
 * Normal return register usage:
 * a0	OPTEE_SMC_RETURN_OK
 * a1	Upper 32bit of a 64bit Shared memory cookie
 * a2	Lower 32bit of a 64bit Shared memory cookie
 * a3-7	Preserved
 *
 * Cache empty return register usage:
 * a0	OPTEE_SMC_RETURN_ENOTAVAIL
 * a1-7	Preserved
 *
 * Not idle return register usage:
 * a0	OPTEE_SMC_RETURN_EBUSY
 * a1-7	Preserved
 */
#define OPTEE_SMC_FUNCID_DISABLE_SHM_CACHE	10
#define OPTEE_SMC_DISABLE_SHM_CACHE \
	OPTEE_SMC_FAST_CALL_VAL(OPTEE_SMC_FUNCID_DISABLE_SHM_CACHE)

struct optee_smc_disable_shm_cache_result {
	unsigned long status;
	unsigned long shm_upper32;
	unsigned long shm_lower32;
	unsigned long reserved0;
};

/*
 * Enable cache of shared memory objects
 *
 * Secure world can cache frequently used shared memory objects, for
 * example objects used as RPC arguments. When secure world is idle this
 * function returns OPTEE_SMC_RETURN_OK and the cache is enabled. If
 * secure world isn't idle OPTEE_SMC_RETURN_EBUSY is returned.
 *
 * Call register usage:
 * a0	SMC Function ID, OPTEE_SMC_ENABLE_SHM_CACHE
 * a1-6	Not used
 * a7	Hypervisor Client ID register
 *
 * Normal return register usage:
 * a0	OPTEE_SMC_RETURN_OK
 * a1-7	Preserved
 *
 * Not idle return register usage:
 * a0	OPTEE_SMC_RETURN_EBUSY
 * a1-7	Preserved
 */
#define OPTEE_SMC_FUNCID_ENABLE_SHM_CACHE	11
#define OPTEE_SMC_ENABLE_SHM_CACHE \
	OPTEE_SMC_FAST_CALL_VAL(OPTEE_SMC_FUNCID_ENABLE_SHM_CACHE)

/*
 * Resume from RPC (for example after processing a foreign interrupt)
 *
 * Call register usage:
 * a0	SMC Function ID, OPTEE_SMC_CALL_RETURN_FROM_RPC
 * a1-3	Value of a1-3 when OPTEE_SMC_CALL_WITH_ARG returned
 *	OPTEE_SMC_RETURN_RPC in a0
 *
 * Return register usage is the same as for OPTEE_SMC_*CALL_WITH_ARG above.
 *
 * Possible return values
 * OPTEE_SMC_RETURN_UNKNOWN_FUNCTION	Trusted OS does not recognize this
 *					function.
 * OPTEE_SMC_RETURN_OK			Original call completed, result
 *					updated in the previously supplied.
 *					struct optee_msg_arg
 * OPTEE_SMC_RETURN_RPC			Call suspended by RPC call to normal
 *					world.
 * OPTEE_SMC_RETURN_ERESUME		Resume failed, the opaque resume
 *					information was corrupt.
 */
#define OPTEE_SMC_FUNCID_RETURN_FROM_RPC	3
#define OPTEE_SMC_CALL_RETURN_FROM_RPC \
	OPTEE_SMC_STD_CALL_VAL(OPTEE_SMC_FUNCID_RETURN_FROM_RPC)

#define OPTEE_SMC_RETURN_RPC_PREFIX_MASK	0xFFFF0000
#define OPTEE_SMC_RETURN_RPC_PREFIX		0xFFFF0000
#define OPTEE_SMC_RETURN_RPC_FUNC_MASK		0x0000FFFF

#define OPTEE_SMC_RETURN_GET_RPC_FUNC(ret) \
	((ret) & OPTEE_SMC_RETURN_RPC_FUNC_MASK)

#define OPTEE_SMC_RPC_VAL(func)		((func) | OPTEE_SMC_RETURN_RPC_PREFIX)

/*
 * Allocate memory for RPC parameter passing. The memory is used to hold a
 * struct optee_msg_arg.
 *
 * "Call" register usage:
 * a0	This value, OPTEE_SMC_RETURN_RPC_ALLOC
 * a1	Size in bytes of required argument memory
 * a2	Not used
 * a3	Resume information, must be preserved
 * a4-5	Not used
 * a6-7	Resume information, must be preserved
 *
 * "Return" register usage:
 * a0	SMC Function ID, OPTEE_SMC_CALL_RETURN_FROM_RPC.
 * a1	Upper 32bits of 64bit physical pointer to allocated
 *	memory, (a1 == 0 && a2 == 0) if size was 0 or if memory can't
 *	be allocated.
 * a2	Lower 32bits of 64bit physical pointer to allocated
 *	memory, (a1 == 0 && a2 == 0) if size was 0 or if memory can't
 *	be allocated
 * a3	Preserved
 * a4	Upper 32bits of 64bit Shared memory cookie used when freeing
 *	the memory or doing an RPC
 * a5	Lower 32bits of 64bit Shared memory cookie used when freeing
 *	the memory or doing an RPC
 * a6-7	Preserved
 */
#define OPTEE_SMC_RPC_FUNC_ALLOC	0
#define OPTEE_SMC_RETURN_RPC_ALLOC \
	OPTEE_SMC_RPC_VAL(OPTEE_SMC_RPC_FUNC_ALLOC)

/*
 * Free memory previously allocated by OPTEE_SMC_RETURN_RPC_ALLOC
 *
 * "Call" register usage:
 * a0	This value, OPTEE_SMC_RETURN_RPC_FREE
 * a1	Upper 32bits of 64bit shared memory cookie belonging to this
 *	argument memory
 * a2	Lower 32bits of 64bit shared memory cookie belonging to this
 *	argument memory
 * a3-7	Resume information, must be preserved
 *
 * "Return" register usage:
 * a0	SMC Function ID, OPTEE_SMC_CALL_RETURN_FROM_RPC.
 * a1-2	Not used
 * a3-7	Preserved
 */
#define OPTEE_SMC_RPC_FUNC_FREE		2
#define OPTEE_SMC_RETURN_RPC_FREE \
	OPTEE_SMC_RPC_VAL(OPTEE_SMC_RPC_FUNC_FREE)

/*
 * Deliver foreign interrupt to normal world.
 *
 * "Call" register usage:
 * a0	OPTEE_SMC_RETURN_RPC_FOREIGN_INTR
 * a1-7	Resume information, must be preserved
 *
 * "Return" register usage:
 * a0	SMC Function ID, OPTEE_SMC_CALL_RETURN_FROM_RPC.
 * a1-7	Preserved
 */
#define OPTEE_SMC_RPC_FUNC_FOREIGN_INTR		4
#define OPTEE_SMC_RETURN_RPC_FOREIGN_INTR \
	OPTEE_SMC_RPC_VAL(OPTEE_SMC_RPC_FUNC_FOREIGN_INTR)

/*
 * Do an RPC request. The supplied struct optee_msg_arg tells which
 * request to do and the parameters for the request. The following fields
 * are used (the rest are unused):
 * - cmd		the Request ID
 * - ret		return value of the request, filled in by normal world
 * - num_params		number of parameters for the request
 * - params		the parameters
 * - param_attrs	attributes of the parameters
 *
 * "Call" register usage:
 * a0	OPTEE_SMC_RETURN_RPC_CMD
 * a1	Upper 32bit of a 64bit Shared memory cookie holding a
 *	struct optee_msg_arg, must be preserved, only the data should
 *	be updated
 * a2	Lower 32bit of a 64bit Shared memory cookie holding a
 *	struct optee_msg_arg, must be preserved, only the data should
 *	be updated
 * a3-7	Resume information, must be preserved
 *
 * "Return" register usage:
 * a0	SMC Function ID, OPTEE_SMC_CALL_RETURN_FROM_RPC.
 * a1-2	Not used
 * a3-7	Preserved
 */
#define OPTEE_SMC_RPC_FUNC_CMD		5
#define OPTEE_SMC_RETURN_RPC_CMD \
	OPTEE_SMC_RPC_VAL(OPTEE_SMC_RPC_FUNC_CMD)

/* Returned in a0 */
#define OPTEE_SMC_RETURN_UNKNOWN_FUNCTION 0xFFFFFFFF

/* Returned in a0 only from Trusted OS functions */
#define OPTEE_SMC_RETURN_OK		0x0
#define OPTEE_SMC_RETURN_ETHREAD_LIMIT	0x1
#define OPTEE_SMC_RETURN_EBUSY		0x2
#define OPTEE_SMC_RETURN_ERESUME	0x3
#define OPTEE_SMC_RETURN_EBADADDR	0x4
#define OPTEE_SMC_RETURN_EBADCMD	0x5
#define OPTEE_SMC_RETURN_ENOMEM		0x6
#define OPTEE_SMC_RETURN_ENOTAVAIL	0x7
#define OPTEE_SMC_RETURN_IS_RPC(ret)	__optee_smc_return_is_rpc((ret))

static inline bool __optee_smc_return_is_rpc(u32 ret)
{
	return ret != OPTEE_SMC_RETURN_UNKNOWN_FUNCTION &&
	       (ret & OPTEE_SMC_RETURN_RPC_PREFIX_MASK) ==
			OPTEE_SMC_RETURN_RPC_PREFIX;
}

#endif /* OPTEE_SMC_H */
