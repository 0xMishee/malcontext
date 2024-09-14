cmake_minimum_required(VERSION 3.28)

#cmake -G "Ninja" -DCMAKE_BUILD_TYPE=Debug ..
set(CMAKE_TOOLCHAIN_FILE "E:/vcpkg/vcpkg/scripts/buildsystems/vcpkg.cmake")
set(VCPKG_TARGET_TRIPLET "x64-windows")

# Set the project name and specify the language
set(CMAKE_C_COMPILER "clang")
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

# Debugging only
set(CMAKE_VERBOSE_MAKEFILE ON)

#Compiler flags
if (CMAKE_C_COMPILER_ID MATCHES "Clang")
  set(SANITIZER_FLAGS "-fsanitize=address,undefined")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SANITIZER_FLAGS}")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${SANITIZER_FLAGS}")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -rtlib=compiler-rt")
endif()


# Set the project name and specify the language
project(MalwareContext C)

include_directories(include)

# Find and configure CURL library
find_package(CURL CONFIG REQUIRED)
find_package(cJSON CONFIG REQUIRED)
find_package(unofficial-b64 CONFIG REQUIRED)


# Collect all source files
file(GLOB SOURCES "src/*.c" "src/api/*.c")
set(MAIN_EXECUTABLE_SOURCE "src/main.c")

# Remove the main executable source file from the SOURCES list
list(REMOVE_ITEM SOURCES ${MAIN_EXECUTABLE_SOURCE})

# Add the main executable with all other source files
add_executable(MalwareContext ${MAIN_EXECUTABLE_SOURCE} ${SOURCES})
set_target_properties(MalwareContext PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
    RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_SOURCE_DIR}/bin
    RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/Debug
)

# Link the CURL library to the executable
target_link_libraries(MalwareContext PRIVATE unofficial::b64::b64)
target_link_libraries(MalwareContext PRIVATE CURL::libcurl)
target_link_libraries(MalwareContext PRIVATE cjson)
