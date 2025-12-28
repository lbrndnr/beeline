#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/bpf.h>
#include <linux/btf.h>

#include "base64url.h"
#include "hpack.h"

BTF_KFUNCS_START(beeline_kfunc_btf_ids)

BTF_ID_FLAGS(func, bl_base64url_encode, KF_RCU)
BTF_ID_FLAGS(func, bl_base64url_decode, KF_RCU)
BTF_ID_FLAGS(func, bl_hpack_decode, KF_RCU)

BTF_KFUNCS_END(beeline_kfunc_btf_ids)

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("The beeline kernel module exposes coding schemes to eBPF.");
MODULE_VERSION("1.0");
