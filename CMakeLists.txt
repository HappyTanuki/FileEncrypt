cmake_minimum_required (VERSION 3.16)
set(PROJECT_NAME "FileEncrypt")
project(${PROJECT_NAME} LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(BOOST_EXCLUDE_LIBRARIES nowide)
set(BUILD_TESTING ON)

set(DPP_BUILD_TEST OFF)

set(CXXOPTS_URL "https://raw.githubusercontent.com/jarro2783/cxxopts/refs/heads/master/include/cxxopts.hpp")
set(CXXOPTS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/include/cxxopts.hpp")

# 다운로드
file(DOWNLOAD
    ${CXXOPTS_URL}
    ${CXXOPTS_FILE}
    SHOW_PROGRESS
    STATUS download_status
    TLS_VERIFY ON
)

include(CTest)
enable_testing()

file(GLOB_RECURSE SOURCES "src/*.cpp" "src/*.cxx" "src/*.cc")
list(FILTER SOURCES EXCLUDE REGEX "src/main.cc")

add_library(${PROJECT_NAME}_lib STATIC ${SOURCES})
set_target_properties(${PROJECT_NAME}_lib PROPERTIES OUTPUT_NAME "FileEncrypt")

target_include_directories(${PROJECT_NAME}_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_precompile_headers(${PROJECT_NAME}_lib PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include/precomp.h")

if(WIN32)
    target_link_libraries(${PROJECT_NAME}_lib PUBLIC ws2_32)
endif()
if(UNIX AND NOT APPLE)
    set_target_properties(${PROJECT_NAME}_lib PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "$ORIGIN"
        SKIP_BUILD_RPATH FALSE
        BUILD_RPATH "$ORIGIN"
    )
endif()
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-D_DEBUG)
endif()

add_executable(${PROJECT_NAME} "src/main.cc")

target_link_libraries(${PROJECT_NAME} PUBLIC ${PROJECT_NAME}_lib)

if(NOT WIN32)
    target_compile_options(${PROJECT_NAME}_lib PRIVATE -march=native)
    target_compile_options(${PROJECT_NAME} PRIVATE -march=native)
endif()

add_subdirectory(tests)
