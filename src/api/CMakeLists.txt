add_library(brovfs_api STATIC
    api.cpp
    host_class.cpp
    native_vfs_scan.cpp
    native_vfs_ops.cpp
    native_vfs_trash.cpp
    native_vfs_watch.cpp
    native_vfs_model.cpp
    native_vfs_misc.cpp
    native_vfs_usage.cpp
)

target_include_directories(brovfs_api PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../include>
)

target_link_libraries(brovfs_api PUBLIC
    brovfs
    bronze_runtime_shared
)

target_compile_features(brovfs_api PUBLIC cxx_std_20)

if(MSVC)
    target_compile_options(brovfs_api PRIVATE /W4 /permissive- /utf-8 /MP)
else()
    target_compile_options(brovfs_api PRIVATE -Wall -Wextra -Wpedantic)
endif()
