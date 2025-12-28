#include <asm/errno.h>

static const char base64url_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

__bpf_kfunc_start_defs();

__bpf_kfunc int bl_base64url_encode(const u8 *src, u32 src__sz, char *dst, u32 dst__sz) {
	if (dst__sz < 4*(src__sz/3))
		return -EINVAL;

	u32 ac = 0;
	int bits = 0;
	int i;
	char *cp = dst;

	for (i = 0; i < src__sz; i++) {
		ac = (ac << 8) | src[i];
		bits += 8;
		do {
			bits -= 6;
			*cp++ = base64url_table[(ac >> bits) & 0x3f];
		} while (bits >= 6);
	}
	if (bits) {
		*cp++ = base64url_table[(ac << (6 - bits)) & 0x3f];
		bits -= 6;
	}

	return cp - dst;
}

__bpf_kfunc int bl_base64url_decode(const u8 *src, u32 src__sz, char *dst, u32 dst__sz) {
    if (dst__sz < 3*(src__sz/4))
		return -EINVAL;

    u32 ac = 0;
	int bits = 0;
	int i;
	char *bp = dst;

	for (i = 0; i < src__sz; i++) {
		const char *p = strchr(base64url_table, src[i]);

		if (p == NULL || src[i] == 0)
			return -1;
		ac = (ac << 6) | (p - base64url_table);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			*bp++ = (u8)(ac >> bits);
		}
	}
	if (ac & ((1 << bits) - 1))
		return -1;
	return bp - dst;
}

__bpf_kfunc_end_defs();
