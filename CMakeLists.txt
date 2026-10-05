cmake_minimum_required(VERSION 3.24)

project(brovfs VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR AND MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

set(BROVFS_SOURCES
    src/file_ops.cpp
    src/mime.cpp
    src/path.cpp
    src/remove.cpp
    src/scanner.cpp
    src/staging.cpp
    src/sys_common.cpp
    src/transfer.cpp
    src/trash_common.cpp
    src/types.cpp
    src/version.cpp
    src/volumes.cpp
    src/walk.cpp
    src/watch_core.cpp
    src/worker.cpp
)

if(WIN32)
    list(APPEND BROVFS_SOURCES
        src/sys_win.cpp
        src/sys_win_copy.cpp
        src/sys_win_meta.cpp
        src/trash_recycle_bin.cpp
        src/volumes_win.cpp
        src/watcher_win.cpp
    )
else()
    list(APPEND BROVFS_SOURCES
        src/sys_posix.cpp
        src/sys_posix_copy.cpp
        src/trash_freedesktop.cpp
        src/volumes_posix.cpp
    )
    if(APPLE)
        enable_language(OBJCXX)
        list(APPEND BROVFS_SOURCES src/watcher_fsevents.cpp src/trash_macos.cpp src/trash_macos_ns.mm)
        set_source_files_properties(src/trash_macos_ns.mm PROPERTIES COMPILE_OPTIONS "-fobjc-arc")
    else()
        list(APPEND BROVFS_SOURCES src/watcher_inotify.cpp)
    endif()
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

if(MSVC)
    target_compile_options(brovfs PRIVATE /W4 /permissive- /utf-8 /MP)
else()
    target_compile_options(brovfs PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(WIN32)
    # Windows 10 1809+ APIs (FileDispositionInfoEx with IGNORE_READONLY, FileIdExtdDirectoryInfo);
    # each has a runtime fallback.
    target_compile_definitions(brovfs PRIVATE _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000006 UNICODE _UNICODE)
    target_link_libraries(brovfs PUBLIC shell32 ole32 advapi32)
else()
    find_package(Threads REQUIRED)
    target_link_libraries(brovfs PUBLIC Threads::Threads)
    if(APPLE)
        target_link_libraries(brovfs PUBLIC "-framework CoreServices" "-framework Foundation")
    endif()
endif()

option(BROVFS_BUILD_TESTS "Build the brovfs test suite" ON)
if(BROVFS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
