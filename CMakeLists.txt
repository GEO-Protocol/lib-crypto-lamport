cmake_minimum_required(VERSION 3.6)

set(SOURCE_FILES
        src/memory.h
        src/memory.cpp
        src/lamportscheme.h
        src/lamportscheme.cpp
        src/lamportkeys.h
        src/lamportkeys.cpp
        )

add_library(lamport ${SOURCE_FILES})