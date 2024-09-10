cmake_minimum_required(VERSION 3.28)

#cmake -G "MinGW Makefiles" -DCMAKE_C_COMPILER="C:\\msys64\\mingw64\\bin\\gcc.exe" ..
set(CMAKE_TOOLCHAIN_FILE "E:/vcpkg/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")

# Set the project name and specify the language
project(MalwareContext LANGUAGES C)

# Set some shiet up
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_VERBOSE_MAKEFILE ON)

# Add the include directory
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

# Enable testing
enable_testing()
add_test(NAME HelpFlagTest COMMAND MalwareContext -h)
add_test(NAME YaraRuleTest COMMAND MalwareContext -y)
add_test(NAME ContextTest COMMAND MalwareContext -context)
add_test(NAME SearchTest COMMAND MalwareContext -search "b1f2068201c29f3b00aeedc0911498043d7c204a860ca16b3fef47fc19fc2b22")