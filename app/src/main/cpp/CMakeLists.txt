cmake_minimum_required(VERSION 3.22.1)
project(envscan)

set(CMAKE_CXX_STANDARD 17)

# Detection techniques live in a plain C++ library next to this file; the JNI
# adapter (envscan.cpp) is the only Android-specific part.
set(PROBES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/probes)
if(NOT EXISTS ${PROBES_DIR}/probes.h)
    message(FATAL_ERROR "probe library not found at ${PROBES_DIR}")
endif()

add_library(envscan SHARED
        envscan.cpp
        ${PROBES_DIR}/probes.cpp
        ${PROBES_DIR}/probes_more.cpp
        ${PROBES_DIR}/probe_util.cpp)
target_include_directories(envscan PRIVATE ${PROBES_DIR})
find_library(log-lib log)
target_link_libraries(envscan ${log-lib})
target_compile_options(envscan PRIVATE -Wall -Wextra -fvisibility=hidden)
