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
    test_volumes
    test_watcher
    test_metadata
    test_deep
    test_dsstore
    test_model
    test_undo
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
