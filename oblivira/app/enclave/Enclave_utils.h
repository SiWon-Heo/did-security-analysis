#ifndef __ENCLAVE_UTILS_H__
#define __ENCLAVE_UTILS_H__

#include "sgx_trts.h"
#include "Enclave_t.h"

#include "PathORAM/PathORAM.hpp"
#include "PathORAM/DID_Map.hpp"
#include "../global_config.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_fprintf fprintf
#define mbedtls_printf printf
#define mbedtls_snprintf snprintf
#endif

void gen_eph_did(const int len, char *eph_did);
void initialize_cache(uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t recursion_data_size, int8_t recursion_levels, uint8_t Z);
int cache_access(char *did, char *did_doc, char op_type);

#endif