cmake_minimum_required(VERSION 3.16)
project(enclaves LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 11)
add_library(enclaves
        AuthEnclave.cpp
        AuthEnclave.h)
target_include_directories(enclaves PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/../gtest/googletest/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../libsodium/src/libsodium/include"
        )

add_executable(encrypt-enclave encrypt-enclave.cpp)
target_link_libraries(encrypt-enclave sodium)
target_include_directories(encrypt-enclave PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/../libsodium/src/libsodium/include"
        )
add_executable(test-enclaves test-enclaves.cpp)
target_link_libraries(test-enclaves enclaves sodium gtest_main)
target_include_directories(test-enclaves PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/../gtest/googletest/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../libsodium/src/libsodium/include"
        )