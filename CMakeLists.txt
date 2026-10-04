cmake_minimum_required(VERSION 3.24)

project(brovfs VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(MSVC)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    add_compile_options(
        $<$<COMPILE_LANGUAGE:CXX>:/MP>
        $<$<COMPILE_LANGUAGE:CXX>:/permissive->
        $<$<COMPILE_LANGUAGE:CXX>:/utf-8>
        $<$<COMPILE_LANGUAGE:CXX>:/W4>
    )
    if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()
else()
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
    )
endif()

set(BROVFS_SOURCES
    src/version.cpp
    src/types.cpp
    src/scanner.cpp
    src/file_ops.cpp
    src/reflink.cpp
    src/trash_common.cpp
    src/trash_freedesktop.cpp
    src/volumes.cpp
    src/mime.cpp
    src/vfs.cpp
)

if(WIN32)
    list(APPEND BROVFS_SOURCES
        src/scanner_win.cpp
        src/trash_win.cpp
        src/volumes_win.cpp
    )
else()
    list(APPEND BROVFS_SOURCES
        src/scanner_posix.cpp
        src/volumes_posix.cpp
    )
endif()

add_library(brovfs STATIC ${BROVFS_SOURCES})
add_library(brovfs::brovfs ALIAS brovfs)

target_include_directories(brovfs
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

if(WIN32)
    target_link_libraries(brovfs PUBLIC shell32 ole32)
endif()

option(BROVFS_BUILD_TESTS "Build brovfs test suite" ON)
if(BROVFS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
