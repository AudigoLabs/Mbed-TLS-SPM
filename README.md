# Mbed-TLS-SPM

This is an SPM wrapper around [mbedtls](https://github.com/Mbed-TLS/mbedtls) plus a C-based set of client APIs.

This repository is heavily inspired by [mbedTLS-iOS](https://github.com/simplisafe/mbedTLS-iOS) but moves all the
wrapper logic to the mbedtls_client.c with a single opaque pointer being passed up to the Swift layer for better memory
management.
