#pragma once

#define MBEDTLS_CLIENT_READ_SIZE        (16*1024)

typedef void* mbedtls_client_handle_t;

mbedtls_client_handle_t mbedtls_client_init(
    int transport,
    int* cipher_suites,
    int num_cipher_suites,
    const unsigned char* psk,
    int psk_len,
    const char* psk_id,
    int psk_id_len,
    void (*debug_func)(void*, int, const char *, int, const char *),
    void* io_context,
    int (*send_func)(void*, const unsigned char* buf, unsigned long len),
    int (*recv_func)(void*, unsigned char* buf, unsigned long len)
);

void mbedtls_client_free(mbedtls_client_handle_t handle);

int mbedtls_client_handshake_step(mbedtls_client_handle_t handle);

int mbedtls_client_get_handshake_state(mbedtls_client_handle_t handle);

int mbedtls_client_write(mbedtls_client_handle_t handle, const unsigned char* data, unsigned long length);

int mbedtls_client_read(mbedtls_client_handle_t handle, unsigned char* data, unsigned long length);
