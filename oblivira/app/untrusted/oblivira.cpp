/*
 *  SSL server demonstration program using pthread for handling multiple
 *  clients.
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#include <stdlib.h>

#include <atomic>
#include <csignal>
#include <iostream>
#include <chrono>

#include "../global_config.h"

/***** Enclave *****/
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "untrusted_utils.h"

sgx_enclave_id_t global_eid;

/***** mbedtls *****/
#include "mbedtls/error.h"
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"

#define mbedtls_fprintf fprintf
#define mbedtls_printf printf
#define mbedtls_snprintf snprintf

/***** HTTPD *****/
#define HTTPSERVER_IMPL
#include "httpserver.h"

/***** libcurl *****/
#include <curl/curl.h>
#define UNIRESOLVER_URL "http://localhost:8080/1.0/identifiers/"

/***** jsopcpp *****/
#include "json.h"

/***** thread *****/
#include <pthread.h>
#include <thread>

typedef struct {
    int active;
    thread_info_t data;
    pthread_t thread;
} pthread_info_t;

static pthread_info_t threads[MAX_NUM_THREADS];

/***** universal resolver *****/
typedef struct {
    bool empty = true;
    char base_addr[MAX_BASE_ADDR_SIZE];
    char query[MAX_QUERY_SIZE];
} uniresolver_response_t;

static uniresolver_response_t uniresolver_responses[MAX_NUM_THREADS];

/***** chache *****/
#include "LocalStorage.hpp"
LocalStorage *ls;


/***** utils *****/
#define proxy_service_print(fmt, args...)                                \
    do {                                                                 \
        printf("[UNTRUSTED][PROXY_SERVICE][%s] " fmt, __func__, ##args); \
    } while (0)
#define did_service_print(fmt, args...)                                \
    do {                                                               \
        printf("[UNTRUSTED][DID_SERVICE][%s] " fmt, __func__, ##args); \
    } while (0)
#define COLOR_GREEN "\e[32m"
#define COLOR_NORMAL "\e[0m"
#define COLOR_RED "\e[31m"

/***** namespace *****/
using std::cerr;
using std::cout;
using std::endl;
using std::exit;
using std::string;

/***** ocall functions *****/
int ocall_query_to_uniresolver(long thread_id, char *eph_did, uint32_t eph_did_size)
{
    int i;
    CURL *curl;
    CURLcode ret;
    string header_string, body_string;

    for (i = 0; i < MAX_NUM_THREADS; i++) {
        if (threads[i].thread == thread_id)
            break;
    }

    if (i == MAX_NUM_THREADS) {
        //cout << "[get_query_info] There is no matching thread for given thread id" << endl;
        return -1;
    } else {
        memcpy(threads[i].data.eph_did, eph_did, eph_did_size);
    }

    curl = curl_easy_init();
    if (!curl)
        return -1;

    string url = UNIRESOLVER_URL;
    url.insert(url.length(), eph_did);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    ret = curl_easy_perform(curl);
    if (ret == CURLE_OK)
    {
        //cout << "\n[UNTRUSTED][DID_SERVICE][get_query_info] curl SUCCESS: " << url << endl;
    }
    else
    {
        //cerr << "\n[UNTRUSTED][DID_SERVICE][get_query_info][Error Code " << ret << "] curl ERROR: " << url << endl;
    }

    curl_easy_cleanup(curl);

    return ret;
}

int ocall_get_query_info(long thread_id, char *base_addr, char *query, uint32_t base_addr_size, uint32_t query_size) {
    int i;
    for (i = 0; i < MAX_NUM_THREADS; i++)
    {
        if (threads[i].thread == thread_id)
            break;
    }
    if (i == 5)
    {
        //cout << "[get_query_info] There is no matching thread for given thread id" << endl;
        return -1;
    }

    while(uniresolver_responses[i].empty) {}

    memcpy(base_addr, uniresolver_responses[i].base_addr, base_addr_size);
    memcpy(query, uniresolver_responses[i].query, query_size);
    uniresolver_responses[i].empty = true;

    return 0;
}


uint8_t ocall_uploadBucket(unsigned char* serialized_bucket, uint32_t bucket_size, uint32_t label, unsigned char* hash, uint32_t hash_size, uint32_t size_for_level, uint8_t recursion_level) {
    ls->uploadBucket(label, serialized_bucket, size_for_level, hash, hash_size, recursion_level);
    return 0;
}

uint8_t ocall_uploadPath(unsigned char* path_array, uint32_t path_size, uint32_t leaf_label, unsigned char* path_hash, uint32_t path_hash_size, uint8_t level, uint32_t D_level) {
    ls->uploadPath(leaf_label, path_array, path_hash, level, D_level);
    return 0;
}

uint8_t ocall_downloadBucket(unsigned char* serialized_bucket, uint32_t bucket_size, uint32_t label, unsigned char* hash, uint32_t hash_size, uint32_t size_for_level, uint8_t recursion_level) {
    ls->downloadBucket(label, serialized_bucket, size_for_level, hash, hash_size, recursion_level);
    return 0;
}

uint8_t ocall_downloadPath(unsigned char* path_array, uint32_t path_size, uint32_t leaf_label, unsigned char *path_hash, uint32_t path_hash_size, uint8_t level, uint32_t D_level) {
    ls->downloadPath(leaf_label, path_array, path_hash, path_hash_size, level, D_level);
    return 0;
}

void ocall_buildFetchChildHash(uint32_t left, uint32_t right, unsigned char* lchild, unsigned char* rchild, uint32_t hash_size, uint32_t recursion_level) {
    ls->fetchHash(left, lchild, hash_size, recursion_level);
    ls->fetchHash(right, rchild, hash_size, recursion_level);
}


/***** functions used in main() *****/
void *handle_ssl_connection(void *data)
{
    unsigned long thread_id = pthread_self();
    thread_info_t *thread_info = (thread_info_t *)data;
    int ret;

    //sleep(2);
    ecall_ssl_conn_handle(global_eid, thread_id, thread_info);    

    return (NULL);
}

static int thread_create(mbedtls_net_context *client_fd)
{
    int ret, i;

    // check thread list and find empty thread space
    for (i = 0; i < MAX_NUM_THREADS; i++)
    {
        // in case of find empty thread space
        if (threads[i].active == 0)
            break;

        // in case of find completed thread, wait for termination and clean it up
        if (threads[i].data.thread_complete == 1)
        {
            //mbedtls_printf("  [ main ]  Cleaning up did thread %d\n", i);
            pthread_join(threads[i].thread, NULL);
            memset(&threads[i], 0, sizeof(pthread_info_t));
            break;
        }
    }

    // full thread list, return error value
    if (i == MAX_NUM_THREADS)
        return (-1);

    // intialize the found thread space
    threads[i].active = 1;
    threads[i].data.config = NULL;
    threads[i].data.thread_complete = 0;
    memcpy(&threads[i].data.client_fd, client_fd, sizeof(mbedtls_net_context));

    if ((ret = pthread_create(&threads[i].thread, NULL, handle_ssl_connection, &threads[i].data)) != 0) {
        return (ret);
    }
    return (0);
}

void handle_request(struct http_request_s *request)
{
    // get http body
    http_string_s proxy_req;
    struct http_response_s *response;
    proxy_req = http_request_body(request);
    //proxy_service_print("Received:\n%s\n", proxy_req.buf);

    // send http response to driver
    response = http_response_init();
    http_response_status(response, 200);
    http_response_header(response, "Content-Type", "text/plain");
    http_response_body(response, "OK", sizeof("OK") - 1);
    http_respond(request, response);

    // create JSON parser
    Json::CharReaderBuilder builder;
    const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    Json::Value query_info;

    // parse http request body to get eph did
    reader->parse(proxy_req.buf, proxy_req.buf + proxy_req.len, &query_info, NULL);
    string base_addr = query_info["baseAddress"].asString();
    string identifier = query_info["identifier"].asString();
    string query = query_info["query"].asString();

    int i;
    // find the corresponding did thread
    for (i = 0; i < MAX_NUM_THREADS; i++)
    {
        if (identifier.compare(threads[i].data.eph_did) == 0)
            break;
    }
    if (i == MAX_NUM_THREADS)
    {
        //cout << "[handle_request] There is no matching case for given eph did" << endl;
        return;
    }
    
    // memcpy http request body and ready to resume the corresponding thread
    memcpy(uniresolver_responses[i].base_addr, base_addr.c_str(), sizeof(char)*(proxy_req.len+1));
    memcpy(uniresolver_responses[i].query, query.c_str(), sizeof(query));
    uniresolver_responses[i].empty = false;

    return;
}

std::atomic<bool> quit(false);
void exitGraceful(int) { quit.store(true); }

int init_did_service(mbedtls_net_context *listen_fd, const char *port)
{
    int ret;
    // initialize the object
    ecall_ssl_conn_init(global_eid);
    // initialize threads
    memset(threads, 0, sizeof(threads));

    //did_service_print("Bind on https://localhost:%s/\n", port);
    fflush(stdout);

    ret = ocall_mbedtls_net_bind(listen_fd, NULL, port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0)
        return ret;

    //did_service_print("Waiting for a remote connection\n");

    return 0;
}

struct http_server_s *init_proxy_drv_service()
{
    http_server_s *server;
    server = http_server_init(8081, handle_request);
    http_server_listen_poll(server);
    return server;
}

/***** Program entry point *****/
int main(void)
{
    int ret;
    struct http_server_s *proxy_fd;
    mbedtls_net_context listen_fd, client_fd;

    // initialize SGX
    if (0 != initialize_enclave(&global_eid))
    {
        cerr << "failed to init enclave" << endl;
        exit(-1);
    }

    // initialize cache
    
    ls = new LocalStorage();
    int recursion_levels = computeRecursionLevels(MAX_BLOCKS, RECURSION_DATA_SIZE, MEM_POSMAP_LIMIT);
    uint32_t D = (uint32_t)ceil(log((double)MAX_BLOCKS/SIZE_Z) / log((double)2));
    ls->setParams(MAX_BLOCKS, D, SIZE_Z, STASH_SIZE, DATA_SIZE + ADDITIONAL_METADATA_SIZE, RECURSION_DATA_SIZE + ADDITIONAL_METADATA_SIZE, recursion_levels);
    
    ecall_createNewORAM(global_eid, (uint8_t *)&ret, MAX_BLOCKS, DATA_SIZE, STASH_SIZE, RECURSION_DATA_SIZE, recursion_levels, SIZE_Z);
    
    // initalize libcurl
    curl_global_init(CURL_GLOBAL_ALL);

    // initialize receiving DID request
    ret = init_did_service(&listen_fd, "4433");
    if (ret != 0)
    {
        //mbedtls_printf(" failed\n  ! ocall_mbedtls_net_bind returned %d\n\n", ret);
        exit(-1);
    }
    //cout << "[UNTRUSTED][DID_SERVICE] DID Service Initialized" << endl;

    // initialize DID proxy service
    proxy_fd = init_proxy_drv_service();
    if (proxy_fd == NULL)
    {
        //printf("Failed to init Proxy Driver service\n");
        exit(-1);
    }
    //cout << "[UNTRUSTED][PROXY_SERVICE] Proxy Driver Initialized" << endl;

    // register Ctrl-C handler
    std::signal(SIGINT, exitGraceful);

    // non-block accept
    while (true)
    {
        // check for Ctrl-C flag
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (quit.load())
        {
            cerr << "\nCtrl-C pressed. Quiting..." << endl;
            break;
        }

        // Wait until a client connects
        if (0 != ocall_mbedtls_net_set_nonblock(&listen_fd))
        {
            cerr << "can't set nonblock for the listen socket" << endl;
        }

        // Listen for Proxy Service
        http_server_poll(proxy_fd);

        // Listen for DID Service
        // Listen again until request arrival        
        ret = ocall_mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ)
        {
            ret = 0;
            continue;
        }

        // Acceptance error occurs
        if (ret != 0)
        {
            //mbedtls_printf("  [ main ] failed: ocall_mbedtls_net_accept returned -0x%04x\n", ret);
        }

        if ((ret = thread_create(&client_fd)) != 0)
        {
            //mbedtls_printf("  [ main ]  failed: thread_create returned %d\n", ret);
            ocall_mbedtls_net_free(&client_fd);
            continue;
        }
        ret = 0;
    }

    curl_global_cleanup();
    sgx_destroy_enclave(global_eid);
    return (ret);
}
