cmake_minimum_required(VERSION 3.16)
project(enclaves C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "-g -O -DCONFIGURED")
set(CMAKE_CXX_FLAGS "-g -O -DCONFIGURED")

add_subdirectory(libsodium)
add_subdirectory(src)
add_subdirectory(gtest)
