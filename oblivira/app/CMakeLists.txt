cmake_minimum_required(VERSION 3.0)
project(oblivira)


list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/lib")

find_package(SGX REQUIRED)
add_library(curl STATIC IMPORTED)

add_definitions(-DMBEDTLS_CONFIG_FILE=<config-sgx.h>)    
set(MBEDTLS_SRC_DIR ${PROJECT_SOURCE_DIR}/include/mbedtls)

# set(MBEDTLS_SGX_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/inc/mbedtls/include)
# set(MBEDTLS_SGX_LIBRARY_DIR ${MBEDTLS_SGX_ROOT}/lib)
set(MBEDTLS_SGX_LIB_U ${PROJECT_SOURCE_DIR}/lib/libmbedtls_SGX_u.a)
set(MBEDTLS_SGX_LIB_T ${PROJECT_SOURCE_DIR}/lib/libmbedtls_SGX_t.a)

set(JSONCPP_SRC_DIR ${PROJECT_SOURCE_DIR}/include/jsoncpp)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_subdirectory(untrusted)
add_subdirectory(enclave)

message(STATUS "=> SGX_MODE: " ${SGX_MODE})
message(STATUS "=> SGX_HW: " ${SGX_HW})

# set(MBEDTLS_SGX_INCLUDE_DIR ${MBEDTLS_SGX_ROOT}/include)
# set(MBEDTLS_SGX_LIBRARY_DIR ${MBEDTLS_SGX_ROOT}/lib)
# set(MBEDTLS_SGX_LIB_U ${CMAKE_BINARY_DIR}/ocall/libmbedtls_SGX_u.a)
# set(MBEDTLS_SGX_LIB_T ${CMAKE_BINARY_DIR}/trusted/libmbedtls_SGX_t.a)

# #message(${MBEDTLS_SGX_LIB_U})
# #message(${MBEDTLS_SGX_LIB_T})

# set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
# set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
# set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# add_subdirectory(untrusted)
# add_subdirectory(enclave)
