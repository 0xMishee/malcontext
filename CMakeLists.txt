cmake_minimum_required(VERSION 3.28)
#cmake -G "MinGW Makefiles" -DCMAKE_C_COMPILER="C:\\msys64\\mingw64\\bin\\gcc.exe" ..

# Set the vcpkg toolchain file
set(CMAKE_TOOLCHAIN_FILE "E:/vcpkg/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")

# Set the project name and specify the language
project(Dev VERSION 1.0 LANGUAGES C)

# Set the C standard to C23; New is always better
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED True)

# Ensure that shared libraries are not built
set(BUILD_SHARED_LIBS OFF)

# Add the include directory
include_directories(include)

# Find and configure CURL library
find_package(CURL CONFIG REQUIRED)

# Collect all source files
file(GLOB SOURCES "src/*.c" "src/api/*.c")

# Specify the main executable source file
set(MAIN_EXECUTABLE_SOURCE "src/main.c")

# Remove the main executable source file from the SOURCES list
list(REMOVE_ITEM SOURCES ${MAIN_EXECUTABLE_SOURCE})

# Add the main executable with all other source files
add_executable(Dev ${MAIN_EXECUTABLE_SOURCE} ${SOURCES})

# Link the CURL library to the executable
target_link_libraries(Dev PRIVATE CURL::libcurl)

# Enable testing
enable_testing()
add_test(NAME HelpFlagTest COMMAND Dev -h)
add_test(NAME YaraRuleTest COMMAND Dev -y)