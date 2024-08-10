cmake_minimum_required(VERSION 3.10)

# Set the project name and specify the language
project(MalwareContext C)

// Add the include directory
include_directories(include)

# Add the source files
add_executable(MalwareContext src/main.c)
