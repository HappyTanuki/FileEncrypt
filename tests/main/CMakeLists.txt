set(test_name "encrypt")
set(full_test_name "main/encrypt")
add_executable(encrypt "main.cc")
target_link_libraries(encrypt PRIVATE ${PROJECT_NAME}_lib)
if(NOT WIN32)
    target_compile_options(encrypt PRIVATE -march=native -maes -msse2 -msse3 -mssse3 -msse4.1 -msse4.2)
endif()
add_test(NAME ${full_test_name}
    COMMAND encrypt encrypt -a AES-256-CBC -i compile_commands.json -o encrypted.aes -k key.pem --overwrite --verbose
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
    COMMAND decrypt decrypt -a AES-256-CBC -o output.txt -i encrypted.aes -k key.pem --overwrite --verbose
)
set_tests_properties(${full_test_name} PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(${full_test_name} PROPERTIES LABELS main)
add_dependencies(decrypt copy_test_vectors)

set_tests_properties(main/decrypt PROPERTIES DEPENDS main/encrypt)

set(test_name "hash_match")
set(full_test_name "main/hash_match")
add_executable(hash_match "main.cc")
target_link_libraries(hash_match PRIVATE ${PROJECT_NAME}_lib)
if(NOT WIN32)
    target_compile_options(hash_match PRIVATE -march=native -maes -msse2 -msse3 -mssse3 -msse4.1 -msse4.2)
endif()
add_test(NAME ${full_test_name}
    COMMAND hash_match hash -a SHA-256 --diff output.txt,compile_commands.json --overwrite --verbose
)
set_tests_properties(${full_test_name} PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(${full_test_name} PROPERTIES LABELS main)
add_dependencies(hash_match copy_test_vectors)

set_tests_properties(main/hash_match PROPERTIES DEPENDS main/decrypt)

set(test_name "hash_do_not_match")
set(full_test_name "main/hash_do_not_match")
add_executable(hash_do_not_match "main.cc")
target_link_libraries(hash_do_not_match PRIVATE ${PROJECT_NAME}_lib)
if(NOT WIN32)
    target_compile_options(hash_do_not_match PRIVATE -march=native -maes -msse2 -msse3 -mssse3 -msse4.1 -msse4.2)
endif()
add_test(NAME ${full_test_name}
    COMMAND hash_do_not_match hash -a SHA-256 --diff encrypted.aes,compile_commands.json --overwrite --verbose
)
set_tests_properties(${full_test_name} PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(${full_test_name} PROPERTIES LABELS main)
set_tests_properties(${full_test_name} PROPERTIES WILL_FAIL TRUE)
add_dependencies(hash_do_not_match copy_test_vectors)

set_tests_properties(main/hash_do_not_match PROPERTIES DEPENDS main/hash_match)

set(test_name "hash1")
set(full_test_name "main/hash1")
add_executable(hash1 "main.cc")
target_link_libraries(hash1 PRIVATE ${PROJECT_NAME}_lib)
if(NOT WIN32)
    target_compile_options(hash1 PRIVATE -march=native -maes -msse2 -msse3 -mssse3 -msse4.1 -msse4.2)
endif()
add_test(NAME ${full_test_name}
    COMMAND hash1 hash -a SHA-256 -i compile_commands.json --overwrite --verbose
)
set_tests_properties(${full_test_name} PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(${full_test_name} PROPERTIES LABELS main)
add_dependencies(hash1 copy_test_vectors)

set_tests_properties(main/hash1 PROPERTIES DEPENDS main/decrypt)

set(test_name "hash2")
set(full_test_name "main/hash2")
add_executable(hash2 "main.cc")
target_link_libraries(hash2 PRIVATE ${PROJECT_NAME}_lib)
if(NOT WIN32)
    target_compile_options(hash2 PRIVATE -march=native -maes -msse2 -msse3 -mssse3 -msse4.1 -msse4.2)
endif()
add_test(NAME ${full_test_name}
    COMMAND hash2 hash -a SHA-256 -i output.txt --overwrite --verbose
)
set_tests_properties(${full_test_name} PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(${full_test_name} PROPERTIES LABELS main)
add_dependencies(hash2 copy_test_vectors)

set_tests_properties(main/hash2 PROPERTIES DEPENDS main/decrypt)

set(test_name "hash_validate")
set(full_test_name "main/hash_validate")
add_executable(hash_validate "main.cc")
target_link_libraries(hash_validate PRIVATE ${PROJECT_NAME}_lib)
if(NOT WIN32)
    target_compile_options(hash_validate PRIVATE -march=native -maes -msse2 -msse3 -mssse3 -msse4.1 -msse4.2)
endif()
add_test(NAME ${full_test_name}
    COMMAND hash_validate hash -a SHA-256 --diff compile_commands.hash.txt,output.hash.txt --overwrite --verbose
)
set_tests_properties(${full_test_name} PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(${full_test_name} PROPERTIES LABELS main)
add_dependencies(hash_validate copy_test_vectors)

set_tests_properties(main/hash_validate PROPERTIES DEPENDS main/decrypt)
set_tests_properties(main/hash_validate PROPERTIES DEPENDS main/hash_do_not_match)
set_tests_properties(main/hash_validate PROPERTIES DEPENDS main/hash1)
set_tests_properties(main/hash_validate PROPERTIES DEPENDS main/hash2)