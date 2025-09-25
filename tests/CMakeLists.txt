file(GLOB TEST_SOURCES "*.cpp" "*.cxx" "*.cc")

foreach(test_src ${TEST_SOURCES})
    get_filename_component(test_name ${test_src} NAME_WE)
    add_executable(${test_name} ${test_src})
    target_link_libraries(${test_name} PRIVATE ${BOT_NAME}_lib)
    add_test(NAME ${test_name} COMMAND ${test_name})
    set_tests_properties(${test_name} PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endforeach()

add_subdirectory(sha256)
add_subdirectory(aes)