cmake_minimum_required(VERSION 3.25)
project(BTest C)

set(CMAKE_C_STANDARD 17)
#set(CMAKE_C_FLAGS "-O3")

set(THREADS_PREFER_PTHREAD_FLAG ON)


add_compile_definitions(Debug)
add_definitions(-DSETMONITOR_SCRIPT_PATH="${CMAKE_CURRENT_SOURCE_DIR}/setMonitor.sh")


find_library(PCAP_LIBRARY pcap REQUIRED)
find_package(Threads REQUIRED)

add_executable(BTest main.c
        ../src/logger.c
        ../src/netManager.c
        ../src/netUtils.c
        ../src/queue.c)

target_include_directories(BTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include ../include/BNet ../src/include)
set_target_properties(BTest PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)
target_link_libraries(BTest PRIVATE ${PCAP_LIBRARY} Threads::Threads)