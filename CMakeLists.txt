cmake_minimum_required(VERSION 3.10)
project(cellframe-tool-sign C)
include(cellframe-sdk/cmake/ReadMKFile.cmake)

if(CMAKE_ANDROID_ARCH_ABI STREQUAL "armeabi-v7a" OR CMAKE_ANDROID_ARCH_ABI STREQUAL "x86")
    add_definitions(-D_FILE_OFFSET_BITS=64 -Dfseeko=fseek -Dftello=ftell)
endif()

ReadVariables(version.mk)

execute_process(
    COMMAND git log -1 --format=%h
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    
string(TIMESTAMP BUILD_TIMESTAMP "%d.%m.%Y")
message("Build date: ${BUILD_TIMESTAMP}")
message("Git SHA: ${GIT_COMMIT_HASH}")


add_definitions("-DDAP_VERSION=\"${VERSION_MAJOR}.${VERSION_MINOR}-${VERSION_PATCH}\"")
add_definitions("-DBUILD_TS=\"${BUILD_TIMESTAMP}\"")
add_definitions("-DBUILD_HASH=\"${GIT_COMMIT_HASH}\"")

set(CELLFRAME_MODULES "core chains network cs-none srv srv-datum srv-stake cs-esbocs srv-xchange srv-voting")
set(SPHINCSPLUS_FLEX ON)
option(CELLFRAME_NO_OPTIMIZATION "Build without BMI BMI2 CPU instruction." ON)
set(DAP_CRYPTO_XKCP_PLAINC ON)
include (cellframe-sdk/dap-sdk/cmake/OS_Detection.cmake)
add_subdirectory(cellframe-sdk)
add_subdirectory(cellframe-sdk/dap-sdk)

add_library(${PROJECT_NAME} SHARED "main.c")

set_property(TARGET ${PROJECT_NAME} APPEND_STRING PROPERTY LINK_FLAGS "-D_GNU_SOURCE")

target_link_libraries(${PROJECT_NAME} PUBLIC m cellframe-sdk log)
target_include_directories(${PROJECT_NAME} INTERFACE . /usr/lib/jvm/java-11-openjdk-amd64/include /usr/lib/jvm/java-11-openjdk-amd64/include/linux)