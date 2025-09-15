cmake_minimum_required (VERSION 3.16)
set(BOT_NAME "FileEncrypt")
project(${BOT_NAME} LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(BOOST_EXCLUDE_LIBRARIES nowide)
set(BUILD_TESTING ON)

set(DPP_BUILD_TEST OFF)

enable_testing()

file(GLOB_RECURSE SOURCES "src/*.cpp" "src/*.cxx" "src/*.cc")

add_library(${BOT_NAME}_lib ${SOURCES})

target_include_directories(${BOT_NAME}_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_precompile_headers(${BOT_NAME}_lib PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include/precomp.h")

if(WIN32)
    target_link_libraries(${BOT_NAME}_lib PUBLIC ws2_32)
endif()
if(UNIX AND NOT APPLE)
    set_target_properties(${BOT_NAME}_lib PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "$ORIGIN"
        SKIP_BUILD_RPATH FALSE
        BUILD_RPATH "$ORIGIN"
    )
endif()

add_executable(${BOT_NAME} ${SOURCES})

target_link_libraries(${BOT_NAME} PUBLIC ${BOT_NAME}_lib)

add_subdirectory(tests)