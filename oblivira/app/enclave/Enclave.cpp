#include "enc.h"
#include "ssl/Log.h"
#include "ssl_conn_hdlr.h"
#include "Enclave_utils.h"

#include "sgx_trts.h"
#include "Enclave_t.h"

TLSConnectionHandler *connectionHandler;

void ecall_ssl_conn_init(void)
{
    connectionHandler = new TLSConnectionHandler();
}

void ecall_ssl_conn_handle(long int thread_id, thread_info_t *thread_info)
{
    connectionHandler->handle(thread_id, thread_info);
}

void ecall_ssl_conn_teardown(void) { delete connectionHandler; }


uint8_t ecall_createNewORAM(uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t recursion_data_size, int8_t recursion_levels, uint8_t Z){
    sgx_status_t ocall_status;

    initialize_cache(max_blocks, data_size, stash_size, recursion_data_size, recursion_levels, Z);
    return 0;
}

