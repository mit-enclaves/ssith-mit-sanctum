cmake_minimum_required(VERSION 3.10)
project(pam_enclave LANGUAGES C CXX ASM)
set(CMAKE_CXX_STANDARD 11)

add_executable(test-pam-enclave
        pam-enclave.c
        key.c
        pam-enclave-encrypt-db.c
        pam-enclave-decrypt-db.c
        pam-enclave.h
        test-pam-enclave.cpp)

target_link_libraries(test-pam-enclave sodium sodium_random gtest_main)
target_include_directories(test-pam-enclave PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../security_monitor/api")

add_executable(pam-enclave-main
        pam-enclave.c
        key.c
        pam-enclave-decrypt-db.c
        pam-enclave.h
        pam-enclave-main.c)

target_link_libraries(pam-enclave-main sodium sodium_random)
target_include_directories(pam-enclave-main PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../security_monitor/api")

add_executable(pam-create-db
        pam-create-db.cpp
        key.c
        pam-enclave-encrypt-db.c)
target_link_libraries(pam-create-db sodium sodium_random)

add_executable(pam-enclave
        enclave_entry.S
        pam-enclave.c
        key.c
        pam-enclave-decrypt-db.c
        pam-enclave.h
        enclave_stack.S
        enclave-stubs.c
        )
target_include_directories(pam-enclave PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../security_monitor/api")
target_link_libraries(pam-enclave sodium sm_clib)
set_target_properties(
  pam-enclave PROPERTIES LINK_FLAGS "-nostartfiles -nostdlib -static -Wl,--entry=enclave_entry -Wl,--gc-sections -Wl,--print-gc-sections -Wl,-T${CMAKE_CURRENT_SOURCE_DIR}/enclave.lds")

add_library(pam-enclave-module SHARED
  pam-enclave-module.c
  )
target_include_directories(pam-enclave-module PRIVATE
 "${CMAKE_CURRENT_SOURCE_DIR}/../include"
 "${CMAKE_CURRENT_SOURCE_DIR}/../"
)
