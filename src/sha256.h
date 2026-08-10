/*
 * SPDX-License-Identifier: GPL-2.0
 * sha256.h — minimal SHA-256 (FIPS 180-4) for anticheat baselines.
 */
#ifndef _AC_SHA256_H_
#define _AC_SHA256_H_

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t h[8];
    uint64_t len;          /* total bytes processed */
    uint8_t  buf[64];
    size_t   buflen;
} ac_sha256_ctx;

void ac_sha256_init(ac_sha256_ctx *c);
void ac_sha256_update(ac_sha256_ctx *c, const void *data, size_t len);
void ac_sha256_final(ac_sha256_ctx *c, uint8_t out[32]);

/* one-shot: hex digest of buf, writes 64 chars + NUL into out_hex */
void ac_sha256_hex(const void *buf, size_t len, char out_hex[65]);

#endif /* _AC_SHA256_H_ */
