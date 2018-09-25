cmake_minimum_required(VERSION 3.6)
project(crypto-lamport-test)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")


#
# Platform build options
# (supported platforms are: LINUX | MAC_OS)
#
set(PLATFORM "LINUX")

IF (${PLATFORM} MATCHES "MAC_OS")
    add_definitions(-DMAC_OS)
ENDIF (${PLATFORM} MATCHES "MAC_OS")

IF (${PLATFORM} MATCHES "LINUX")
    add_definitions(-DLINUX)
ENDIF (${PLATFORM} MATCHES "LINUX")


#
# Boost configuration
#
set(Boost_USE_SHARED_LIBS ON)
set(Boost_USE_MULTITHREADED ON)


set(SOURCE_FILES
        main.cpp

        ../src/memory.h
        ../src/memory.cpp
        ../src/lamportscheme.h
        ../src/lamportscheme.cpp
        ../src/lamportkeys.h
        ../src/lamportkeys.cpp
        ../src/keychain.h
        ../src/keychain.cpp)

add_executable(crypto-lamport-test ${SOURCE_FILES})

target_link_libraries(crypto-lamport-test
        -lsodium)
