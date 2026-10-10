# Every test is a real executable exercising the real file system inside scratch directories
# it creates (under BROVFS_TEST_SCRATCH, default: the test's working directory). Checks are
# live in every configuration (no assert()).
#   BROVFS_TEST_SCRATCH2  a directory on a *different* volume, for cross-device moves
#                         (default: the system temp dir on Windows, /dev/shm on Linux, used
#                         only if it really is another device).
set(BROVFS_TESTS
    test_paths
    test_scanner
    test_copy
    test_move
    test_remove
    test_trash
    test_worker
    test_mime
    test_mime_db
    test_volumes
    test_watcher
    test_metadata
    test_deep
    test_dsstore
    test_model
    test_undo
    test_usage
)

foreach(name IN LISTS BROVFS_TESTS)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE brovfs)
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR})
    target_compile_definitions(${name} PRIVATE BROVFS_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
    if(MSVC)
        target_compile_options(${name} PRIVATE /W4 /permissive- /utf-8)
        target_compile_definitions(${name} PRIVATE UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS)
    endif()
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES TIMEOUT 600)
endforeach()

if(WIN32)
    target_link_libraries(test_trash PRIVATE shell32 ole32)
endif()
# Manual oracle, not a ctest: `find dir -type f | probe_mime_tool` vs `file --mime-type -f -`.
add_executable(probe_mime_tool probe_mime_tool.cpp)
target_link_libraries(probe_mime_tool PRIVATE brovfs)
if(MSVC)
    target_compile_options(probe_mime_tool PRIVATE /W4 /permissive- /utf-8)
endif()

if(BROVFS_ENABLE_API)
    add_executable(brovfs_test_api
        test_vfs_api.cpp
    )
    target_include_directories(brovfs_test_api PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/api
        ${PROJECT_SOURCE_DIR}
    )
    target_link_libraries(brovfs_test_api PRIVATE
        brovfs_api
        brovfs
        bronze_runtime_shared
    )
    if(MSVC)
        target_compile_options(brovfs_test_api PRIVATE /W4 /permissive- /utf-8)
        target_compile_definitions(brovfs_test_api PRIVATE UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS)
        add_custom_command(TARGET brovfs_test_api POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:bronze_runtime_shared>
                $<TARGET_FILE_DIR:brovfs_test_api>
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_LINKER_FILE:bronze_runtime_shared>
                $<TARGET_FILE_DIR:brovfs_test_api>
        )
    else()
        target_compile_options(brovfs_test_api PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    if(NOT BRASS_HOST_BACKEND)
        message(STATUS "brovfs: brovfs_test_api not registered (brass has no code generator for this target)")
    else()
        add_test(NAME brovfs_test_api COMMAND brovfs_test_api)
        set_tests_properties(brovfs_test_api PROPERTIES TIMEOUT 120 SKIP_RETURN_CODE 77)

        add_test(NAME brovfs_test_api_gc_stress COMMAND brovfs_test_api)
        set_tests_properties(brovfs_test_api_gc_stress PROPERTIES
            TIMEOUT 120
            SKIP_RETURN_CODE 77
            ENVIRONMENT "BRONZE_GC_STRESS=1;BRONZE_GC_POISON=1"
        )
        if(WIN32)
            set_tests_properties(brovfs_test_api PROPERTIES
                ENVIRONMENT "PATH=$<TARGET_FILE_DIR:bronze_runtime_shared>;$<TARGET_FILE_DIR:brovfs_test_api>;$ENV{PATH}")
            set_property(TEST brovfs_test_api_gc_stress APPEND PROPERTY
                ENVIRONMENT "PATH=$<TARGET_FILE_DIR:bronze_runtime_shared>;$<TARGET_FILE_DIR:brovfs_test_api>;$ENV{PATH}")
        endif()
    endif()
endif()

# Every test executable links no_dialogs.cpp (see the file).
if(WIN32)
    get_property(_test_targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
    foreach(_t IN LISTS _test_targets)
        get_target_property(_type ${_t} TYPE)
        if(_type STREQUAL "EXECUTABLE")
            target_sources(${_t} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/no_dialogs.cpp)
        endif()
    endforeach()
endif()

