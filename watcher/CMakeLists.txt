cmake_minimum_required(VERSION 3.15)
project(marrow_watcher CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W4 /permissive- /EHsc)
    add_compile_definitions(WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

add_library(marrow_watcher SHARED watcher.cpp)
set_target_properties(marrow_watcher PROPERTIES
    OUTPUT_NAME "marrow_watcher"
    PREFIX ""
    SUFFIX ".dll")
