#pragma once

#include <stdio.h>
#include <string.h>
#include <math.h>

#ifdef _MSC_VER
#include <Shlobj.h>
#else
#include <pwd.h>
#include <unistd.h>
#define MAX_PATH FILENAME_MAX
#endif

#include "sgx_error.h"
#include "sgx_urts.h"
#include "sgx_eid.h"     /* sgx_enclave_id_t */

#ifdef HAVE_SGX_UAE_LAUNCH_H
#include "sgx_uae_launch.h"
#else
#include "sgx_uae_service.h"
#endif /* HAVE_SGX_UAE_LAUNCH_H */

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

#if defined(_MSC_VER)
#define TOKEN_FILENAME   "Enclave.token"
#define ENCLAVE_FILENAME "Enclave.signed.dll"
#elif defined(__GNUC__)
#define TOKEN_FILENAME   "enclave.token"
#define ENCLAVE_FILENAME "enclave.signed.so"
#endif

void print_error_message(sgx_status_t ret);
uint8_t computeRecursionLevels(uint32_t max_blocks, uint32_t recursion_data_size, uint64_t onchip_posmap_memory_limit);
int initialize_enclave(sgx_enclave_id_t *eid);

#if defined(_MSC_VER)
int query_sgx_status();
#endif

#if defined(__cplusplus)
extern "C" {
#endif

extern sgx_enclave_id_t global_eid;    /* global enclave id */

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

#if defined(__cplusplus)
}
#endif
