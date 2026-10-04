enable_testing()

set(TESTS
    test_smoke
    test_async_scanner
    test_file_ops
    test_trash
    test_mime
    test_volumes
)

foreach(test_name IN LISTS TESTS)
    add_executable(${test_name} "${test_name}.cpp")
    target_link_libraries(${test_name} PRIVATE brovfs)
    target_include_directories(${test_name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../include")
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
