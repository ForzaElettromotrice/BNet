
cmake_minimum_required(VERSION 3.25)
project(BNet C)

set(CMAKE_C_STANDARD 17)
#set(CMAKE_C_FLAGS "-O3")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/../bin)

add_compile_definitions(Debug)


include_directories(/usr/include)

find_library(PCAP_LIBRARY pcap REQUIRED)

#find_package(Pcap REQUIRED)

add_executable(BNet src/main.c
        src/main.h
        src/netManager.c
        src/netManager.h
        src/logger.c
        src/logger.h
        src/parameters.h
        src/queue.c
        src/queue.h
        src/netUtils.c
        src/netUtils.h)

target_link_libraries(BNet PRIVATE ${PCAP_LIBRARY})
