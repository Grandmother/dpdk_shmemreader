cmake_minimum_required(VERSION 3.0.2)

SET(DPDK_PATH $ENV{DPDK_SRC})
INCLUDE(${CMAKE_CURRENT_SOURCE_DIR}/CMakeListsDPDK.txt NO_POLICY_SCOPE)


set(SOURCE
        lib/memory.c
        lib/session.c
        lib/time.c
        main.c)
set(PRJ_NAME shmem_reader)

project(${PRJ_NAME} C)

set(CMAKE_C_FLAGS "--std=c99")

add_executable(${PRJ_NAME} ${SOURCE})

TARGET_LINK_LIBRARIES(${PRJ_NAME}
        -Wl,--whole-archive
            rte_eal
        -Wl,--as-needed
        -Wl,--no-whole-archive
            pthread dl )
