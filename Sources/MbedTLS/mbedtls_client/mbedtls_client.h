#pragma once

#include <inttypes.h>

#define MBEDTLS_CLIENT_READ_SIZE        (16*1024)

typedef void* mbedtls_client_handle_t;

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
);

void mbedtls_client_free(mbedtls_client_handle_t handle);

int mbedtls_client_handshake(mbedtls_client_handle_t handle);

int mbedtls_client_write(mbedtls_client_handle_t handle, const uint8_t* data, size_t length);

int mbedtls_client_read(mbedtls_client_handle_t handle, uint8_t* data, size_t length);
