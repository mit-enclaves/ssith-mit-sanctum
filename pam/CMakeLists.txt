cmake_minimum_required(VERSION 3.10)
project(pam_enclave LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 11)

add_executable(test-pam-enclave
        pam-enclave.c
        pam-enclave.h
        test-pam-enclave.cpp)

target_link_libraries(test-pam-enclave sodium gtest_main)
