cmake_minimum_required(VERSION 3.28)
project(BNet C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/../bin)

add_executable(BNet src/main.c)
