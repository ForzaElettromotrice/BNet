cmake_minimum_required(VERSION 3.25)
project(BNet C)

set(CMAKE_C_STANDARD 17)
#set(CMAKE_C_FLAGS "-O3")

set(THREADS_PREFER_PTHREAD_FLAG ON)

add_compile_definitions(Debug)

include_directories(${CMAKE_BINARY_DIR}/../lib/BNet/include)

find_library(PCAP_LIBRARY pcap REQUIRED)
find_package(Threads REQUIRED)


add_library(BNetShared SHARED
        src/netManager.c
        src/logger.c
        src/queue.c
        src/netUtils.c
        lib/BNet/include/BNet.h)

target_link_libraries(BNetShared PUBLIC ${PCAP_LIBRARY})
target_link_libraries(BNetShared PRIVATE Threads::Threads)

set_target_properties(BNetShared PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/../lib/BNet/lib OUTPUT_NAME BNet)


add_library(BNetStatic STATIC
        src/netManager.c
        src/logger.c
        src/queue.c
        src/netUtils.c
        lib/BNet/include/BNet.h)


target_link_libraries(BNetStatic PUBLIC ${PCAP_LIBRARY})
target_link_libraries(BNetStatic PRIVATE Threads::Threads)


set_target_properties(BNetStatic PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/../lib/BNet/lib OUTPUT_NAME BNet)

