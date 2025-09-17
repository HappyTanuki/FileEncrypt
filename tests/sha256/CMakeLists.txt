file(GLOB_RECURSE TEST_SOURCES "*.cpp" "*.cxx" "*.cc")

get_filename_component(CURRENT_FOLDER_NAME ${CMAKE_CURRENT_SOURCE_DIR} NAME)

foreach(test_src ${TEST_SOURCES})
    get_filename_component(test_name ${test_src} NAME_WE)
    set(full_test_name "${CURRENT_FOLDER_NAME}/${test_name}")
    add_executable(${test_name} ${test_src})
    target_link_libraries(${test_name} PRIVATE ${BOT_NAME}_lib)
    add_test(NAME ${full_test_name} COMMAND ${test_name})
    set_tests_properties(${full_test_name} PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    set_tests_properties(${full_test_name} PROPERTIES LABELS ${CURRENT_FOLDER_NAME})
endforeach()