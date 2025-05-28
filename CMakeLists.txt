cmake_minimum_required(VERSION 3.25)
project(BNet C)

set(CMAKE_C_STANDARD 17)
#set(CMAKE_C_FLAGS "-O3")


set(BUILD_SHARED "Build shared libraries instead of static" ON)
set(DEBUG_FLAG "Allow debug prints" ON)
set(THREADS_PREFER_PTHREAD_FLAG ON)

if (DEBUG_FLAG)
    add_compile_definitions(Debug)
endif ()

set(LIB_TYPE STATIC)
if (BUILD_SHARED)
    set(LIB_TYPE SHARED)
endif ()

add_definitions(-DSETMONITOR_SCRIPT_PATH="${CMAKE_CURRENT_SOURCE_DIR}/setMonitor.sh")

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/lib/CUtils)

find_library(PCAP_LIBRARY pcap REQUIRED)
find_package(Threads REQUIRED)


add_library(BNet ${LIB_TYPE}
        src/netManager.c
        src/netUtils.c)

target_link_libraries(BNet PUBLIC ${PCAP_LIBRARY} CUtils)
target_link_libraries(BNet PRIVATE Threads::Threads)

set_target_properties(BNet PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib
        OUTPUT_NAME BNet)
target_include_directories(
        BNet PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include/BNet
        BNet PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/include)

