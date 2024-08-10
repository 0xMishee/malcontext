cmake_minimum_required(VERSION 3.10)

# Set the project name and specify the language
project(MalwareContext C)

set(CMAKE_C_COMPILE "C:\\msys64\\mingw64\\bin\\gcc.exe")

# Set the C standard to C23; New is always better
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED True)


#Add the include directory
include_directories(include)

# Collect all source files in the src directory
file(GLOB SOURCES "src/*.c")

# Specify the main executable source file
set(MAIN_EXECUTABLE_SOURCE "src/main.c")

# Remove the main executable source file from the SOURCES list
list(REMOVE_ITEM SOURCES ${MAIN_EXECUTABLE_SOURCE})

# Add the main executable with all other source files
add_executable(MalwareContext ${MAIN_EXECUTABLE_SOURCE} ${SOURCES})