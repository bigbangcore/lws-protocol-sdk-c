cmake_minimum_required(VERSION 3.5.1)
project(lws-protocol-sdk-c)

set(CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}/cmake" CACHE PATH "The path to the cmake directory")
list(APPEND CMAKE_MODULE_PATH ${CMAKE_DIR})

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 14)

# c-algorithms
file(GLOB CAlgorithms_SRC "external_libs/c-algorithms/src/*.c")
include_directories("external_libs/c-algorithms/src/")

# crc
file(GLOB Crc_SRC "external_libs/crc/crc/*.c")
include_directories("external_libs/crc/crc/")

# main
set(src main.c lws_protocol.c lws_protocol.h)
set(src ${src} ${Crc_SRC})
add_executable(lwsp ${src})
target_link_libraries(lwsp pthread sodium mosquitto)
