cmake_minimum_required(VERSION 3.12)
project(lib_crypto_lamport)

set(CMAKE_CXX_STANDARD 14)

include_directories(src)
include_directories(tests)

add_executable(lib_crypto_lamport
    src/lamportkeys.cpp
    src/lamportkeys.h
    src/lamportscheme.cpp
    src/lamportscheme.h
    src/memory.cpp
    src/memory.h
    src/types.h
    tests/bin/crypto-lamport-test
    tests/cmake-build-debug/cmake_install.cmake
    tests/cmake-build-debug/CMakeCache.txt
    tests/cmake-build-debug/crypto-lamport-test.cbp
    tests/cmake-build-debug/Makefile
    tests/catch2.hpp
    tests/CMakeLists.txt
    tests/main.cpp)
