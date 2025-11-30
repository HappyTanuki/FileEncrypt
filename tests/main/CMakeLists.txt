set(test_name "encrypt")
set(full_test_name "main/encrypt")
add_executable(encrypt "main.cc")
target_link_libraries(encrypt PRIVATE ${PROJECT_NAME}_lib)
if(NOT WIN32)
    target_compile_options(encrypt PRIVATE -march=native -maes -msse2 -msse3 -mssse3 -msse4.1 -msse4.2)
endif()
add_test(NAME ${full_test_name}
    COMMAND encrypt encrypt -a AES-256-CTR -i compile_commands.json -p asdf -o encrypted.aes -k key.pem --overwrite
)
set_tests_properties(${full_test_name} PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(${full_test_name} PROPERTIES LABELS main)
add_dependencies(encrypt copy_test_vectors)

set(test_name "decrypt")
set(full_test_name "main/decrypt")
add_executable(decrypt "main.cc")
target_link_libraries(decrypt PRIVATE ${PROJECT_NAME}_lib)
if(NOT WIN32)
    target_compile_options(decrypt PRIVATE -march=native -maes -msse2 -msse3 -mssse3 -msse4.1 -msse4.2)
endif()
add_test(NAME ${full_test_name}
    COMMAND decrypt decrypt -a AES-256-CTR -o output.txt -i encrypted.aes -p asdf -k key.pem --overwrite
)
set_tests_properties(${full_test_name} PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(${full_test_name} PROPERTIES LABELS main)
add_dependencies(decrypt copy_test_vectors)

set_tests_properties(main/decrypt PROPERTIES DEPENDS main/encrypt)