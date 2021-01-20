cmake_minimum_required(VERSION 3.5.1)
project(lws-protocol-sdk-c)

set(CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}/cmake" CACHE PATH "The path to the cmake directory")
list(APPEND CMAKE_MODULE_PATH ${CMAKE_DIR})

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 14)

# test 
set(test_src test.c lws_protocol.c lws_protocol.h crc32.c crc32.h)
add_executable(lwsp ${test_src})
target_link_libraries(lwsp sodium)
