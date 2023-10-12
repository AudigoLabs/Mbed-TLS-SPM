#include "../mbedtls/sha256.h"
#include "../mbedtls/platform_util.h"

#include <assert.h>
#include <string.h>

static int map_result(int res) {
    return res == 1 ? 0 : MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
}

void mbedtls_sha256_init(mbedtls_sha256_context* ctx) {
    const int res = CC_SHA256_Init(ctx);
    assert(res == 1);
}

void mbedtls_sha256_free(mbedtls_sha256_context *ctx) {
    if (ctx == NULL) {
        return;
    }
    memset(ctx, 0, sizeof(*ctx));
}

void mbedtls_sha256_clone(mbedtls_sha256_context* dst, const mbedtls_sha256_context* src) {
    memcpy(dst, src, sizeof(*dst));
}

int mbedtls_sha256_starts_ret(mbedtls_sha256_context* ctx, int is224) {
    if (is224) {
        return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
    }
    return map_result(CC_SHA256_Init(ctx));
}

int mbedtls_internal_sha256_process(mbedtls_sha256_context* ctx, const uint8_t data[64]) {
    return map_result(CC_SHA256_Update(ctx, data, 64));
}

int mbedtls_sha256_update_ret(mbedtls_sha256_context *ctx, const unsigned char *input, size_t ilen) {
    return map_result(CC_SHA256_Update(ctx, input, (unsigned int)ilen));
}

int mbedtls_sha256_finish_ret(mbedtls_sha256_context *ctx, unsigned char output[32]) {
    return map_result(CC_SHA256_Final(output, ctx));
}
