#ifndef __ENCLAVE_UTILS_HPP__
#define __ENCLAVE_UIILS_HPP__

#include "sgx_tcrypto.h"
#include "oasm_lib.h"
#include "../../global_config.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_fprintf fprintf
#define mbedtls_printf printf
#define mbedtls_snprintf snprintf
#endif

void oarraySearch(uint32_t *array, uint32_t loc, uint32_t *leaf, uint32_t newLabel, uint32_t N_level);

#endif