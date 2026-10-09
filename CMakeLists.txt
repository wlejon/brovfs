cmake_minimum_required(VERSION 3.24)

project(brovfs VERSION 0.2.0 LANGUAGES CXX)

# Dependencies (cmake/bro_deps.cmake): an outer project's target wins, else the
# ../<name> working tree beside the top-level project, else the pinned commit,
# fetched at configure.
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/bro_deps.cmake)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# The DLL CRT (/MD, /MDd), as bro uses. brovfs_api's tests link
# bronze_runtime_shared, a DLL whose embed boundary passes C++ objects
# (std::string, ...) both ways: with the static CRT the DLL and the test
# executable each get their own heap, and a Debug build asserts
# (__acrt_first_block == header) the first time one frees the other's memory.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR AND MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
endif()

# Coverage. Scoped to a top-level build: a consumer that add_subdirectory()s
# brovfs has no business having its own build instrumented from in here.
option(BROVFS_COVERAGE "Instrument the build for gcov coverage (GCC/Clang)" OFF)
if(BROVFS_COVERAGE AND PROJECT_IS_TOP_LEVEL)
    if(MSVC)
        message(FATAL_ERROR "BROVFS_COVERAGE requires GCC or Clang (gcov instrumentation); MSVC is unsupported.")
    endif()
    add_compile_options(--coverage -O0 -g)
    add_link_options(--coverage)
    message(STATUS "brovfs: coverage instrumentation ON (-O0)")
endif()

set(BROVFS_SOURCES
    src/aggregate.cpp
    src/collate.cpp
    src/dir_model.cpp
    src/dir_model_view.cpp
    src/ds_store.cpp
    src/file_ops.cpp
    src/mime.cpp
    src/mime_builtin.cpp
    src/mime_db.cpp
    src/mime_smi.cpp
    src/path.cpp
    src/remove.cpp
    src/scanner.cpp
    src/staging.cpp
    src/sys_common.cpp
    src/undo.cpp
    src/transfer.cpp
    src/trash_common.cpp
    src/types.cpp
    src/version.cpp
    src/volume_monitor.cpp
    src/volumes.cpp
    src/walk.cpp
    src/watch_core.cpp
    src/worker.cpp
)

if(WIN32)
    list(APPEND BROVFS_SOURCES
        src/mime_win.cpp
        src/sys_win.cpp
        src/sys_win_copy.cpp
        src/sys_win_meta.cpp
        src/trash_recycle_bin.cpp
        src/volume_monitor_win.cpp
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
        list(APPEND BROVFS_SOURCES src/mime_mac.cpp src/watcher_fsevents.cpp src/trash_macos.cpp src/trash_macos_ns.mm
             src/volume_monitor_mac.cpp)
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
    target_link_libraries(brovfs PUBLIC shell32 ole32 advapi32 user32 shlwapi)
else()
    find_package(Threads REQUIRED)
    target_link_libraries(brovfs PUBLIC Threads::Threads)
    if(APPLE)
        target_link_libraries(brovfs PUBLIC "-framework CoreServices" "-framework Foundation"
                              "-framework DiskArbitration")
    endif()
endif()

# --- Standalone Bronze JavaScript API ---
# On by default only when brovfs is the top-level project. A library that
# consumes brovfs (broapps, brothumb, ...) then never needs bronze for it;
# bro forces BROVFS_ENABLE_API ON itself when it wants the binding.
option(BROVFS_ENABLE_API "Build Bronze JavaScript API" ${PROJECT_IS_TOP_LEVEL})
if(BROVFS_ENABLE_API)
    # bronze (with brass, its code generator) through cmake/bro_deps.cmake: an
    # outer project's target, else ../bronze beside the top-level project, else
    # the pinned commit, fetched at configure.
    bro_dependency(bronze GITHUB wlejon/bronze TARGET bronze_runtime_shared
                   OPTIONS BRONZE_BUILD_SHARED_RUNTIME=ON BRONZE_BUILD_TESTS=OFF)

    add_subdirectory(src/api)
endif()

option(BROVFS_BUILD_TESTS "Build the brovfs test suite" ${PROJECT_IS_TOP_LEVEL})
if(BROVFS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

