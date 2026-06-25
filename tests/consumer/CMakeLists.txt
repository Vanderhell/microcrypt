cmake_minimum_required(VERSION 3.20)
project(microcrypt_consumer C)

find_package(microcrypt CONFIG REQUIRED)

add_executable(consumer main.c)
target_link_libraries(consumer PRIVATE microcrypt::microcrypt)
