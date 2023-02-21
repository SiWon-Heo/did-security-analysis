#ifndef MBEDTLS_SGX_SSL_SERVER_THREAD_H
#define MBEDTLS_SGX_SSL_SERVER_THREAD_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <string>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net.h"
#include "mbedtls/error.h"

#include <sgx_thread.h>

#include "Enclave_utils.h"
#include "ssl_context.h"

using std::string;

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#define HTTP_RESPONSE "HTTP/1.0 200 OK\r\nContent-Type: application/json; Charset=utf-8\r\n\r\n%s"

class TLSConnectionHandler
{
private:
    /* static members */
    const static string pers;

    /* global server state */
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_x509_crt cachain;
    mbedtls_pk_context pkey;

    /* Oblivira metadata */
    char eph_did[MAX_DID_SIZE];
    char base_addr[MAX_BASE_ADDR_SIZE];
    char query[MAX_QUERY_SIZE];
    int info_len; // ??

    /* configuration */
    unsigned int debug_level;

    /* debug callback */
    static void mydebug(void *ctx, int level,
                        const char *file, int line,
                        const char *str);

public:
    TLSConnectionHandler();
    TLSConnectionHandler(unsigned int debug_level) : debug_level(debug_level)
    {
        TLSConnectionHandler();
    }
    ~TLSConnectionHandler();
    void handle(long int, thread_info_t *);
};

#endif //MBEDTLS_SGX_SSL_SERVER_THREAD_H
