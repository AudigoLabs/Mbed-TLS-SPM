#include "mbedtls_client.h"

#include "../mbedtls/ctr_drbg.h"
#include "../mbedtls/debug.h"
#include "../mbedtls/entropy.h"
#include "../mbedtls/ssl.h"
#include "../mbedtls/timing.h"

#include <stdlib.h>
#include <string.h>

_Static_assert(MBEDTLS_CLIENT_READ_SIZE == MBEDTLS_SSL_IN_CONTENT_LEN, "");

typedef struct {
    int* cipher_suites;
    struct mbedtls_ssl_context context;
    struct mbedtls_ssl_config config;
    struct mbedtls_ctr_drbg_context ctr_drbg;
    struct mbedtls_entropy_context entropy;
    struct mbedtls_timing_delay_context timing;
} mbedtls_client_impl_t;

mbedtls_client_handle_t mbedtls_client_init(
    int transport,
    int* cipher_suites,
    int num_cipher_suites,
    const uint8_t* psk,
    int psk_len,
    const char* psk_id,
    int psk_id_len,
    void (*debug_func)(void*, int, const char *, int, const char *),
    void* io_context,
    int (*send_func)(void*, const uint8_t* buf, size_t len),
    int (*recv_func)(void*, uint8_t* buf, size_t len),
    int* err_out
) {
    mbedtls_client_impl_t* impl = malloc(sizeof(mbedtls_client_impl_t));
    memset(impl, 0, sizeof(*impl));
    impl->cipher_suites = calloc(num_cipher_suites + 1, sizeof(int));
    memcpy(impl->cipher_suites, cipher_suites, num_cipher_suites * sizeof(int));
    impl->cipher_suites[num_cipher_suites] = 0;

    mbedtls_ssl_init(&impl->context);
    mbedtls_ssl_config_init(&impl->config);
    mbedtls_ctr_drbg_init(&impl->ctr_drbg);
    mbedtls_entropy_init(&impl->entropy);

    if ((*err_out = mbedtls_ctr_drbg_seed(&impl->ctr_drbg, mbedtls_entropy_func, &impl->entropy, NULL, 0))) {
        mbedtls_client_free(impl);
        return NULL;
    }

    if ((*err_out = mbedtls_ssl_config_defaults(&impl->config, MBEDTLS_SSL_IS_CLIENT, transport, MBEDTLS_SSL_PRESET_DEFAULT))) {
        mbedtls_client_free(impl);
        return NULL;
    }

    mbedtls_ssl_conf_rng(&impl->config, mbedtls_ctr_drbg_random, &impl->ctr_drbg);
    mbedtls_ssl_conf_ciphersuites(&impl->config, impl->cipher_suites);

    if ((*err_out = mbedtls_ssl_conf_psk(&impl->config, psk, psk_len, (const uint8_t*)psk_id, psk_id_len))) {
        mbedtls_client_free(impl);
        return NULL;
    }

    mbedtls_debug_set_threshold(1);
    mbedtls_ssl_conf_dbg(&impl->config, debug_func, NULL);

    if ((*err_out = mbedtls_ssl_setup(&impl->context, &impl->config))) {
        mbedtls_client_free(impl);
        return NULL;
    }

    mbedtls_ssl_set_timer_cb(&impl->context, &impl->timing, mbedtls_timing_set_delay, mbedtls_timing_get_delay);
    mbedtls_ssl_set_bio(&impl->context, io_context, send_func, recv_func, NULL);

    return impl;
}

void mbedtls_client_free(mbedtls_client_handle_t handle) {
    mbedtls_client_impl_t* impl = handle;
    mbedtls_ssl_free(&impl->context);
    mbedtls_ctr_drbg_free(&impl->ctr_drbg);
    mbedtls_entropy_free(&impl->entropy);
    mbedtls_ssl_config_free(&impl->config);
    free(impl->cipher_suites);
    free(impl);
}

int mbedtls_client_handshake_step(mbedtls_client_handle_t handle) {
    mbedtls_client_impl_t* impl = handle;
    return mbedtls_ssl_handshake_step(&impl->context);
}

int mbedtls_client_get_handshake_state(mbedtls_client_handle_t handle) {
    mbedtls_client_impl_t* impl = handle;
    return impl->context.state;
}

int mbedtls_client_write(mbedtls_client_handle_t handle, const unsigned char* data, unsigned long length) {
    mbedtls_client_impl_t* impl = handle;
    return mbedtls_ssl_write(&impl->context, data, length);
}

int mbedtls_client_read(mbedtls_client_handle_t handle, unsigned char* data, unsigned long length) {
    mbedtls_client_impl_t* impl = handle;
    return mbedtls_ssl_read(&impl->context, data, length);
}
