cmake_minimum_required(VERSION 3.13)
project(cpp_conf)

set(CMAKE_CXX_STANDARD 17)

add_library(md6 hash/md6/md6_mode.c hash/md6/md6_compress.c)
add_library(sha3 hash/sha3/sha3.c)
add_library(crc hash/crc/crc32.c)
add_library(city hash/cityHash/city.cpp)
add_library(blake hash/blake/blake512.c)
add_library(murmur hash/murmur/murmurhash3_32.c)

add_executable(cpp_conf main.cpp)

target_link_libraries(cpp_conf md6)
target_link_libraries(cpp_conf sha3)
target_link_libraries(cpp_conf crc)
target_link_libraries(cpp_conf city)
target_link_libraries(cpp_conf blake)
target_link_libraries(cpp_conf murmur)