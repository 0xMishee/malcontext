
cmake_minimum_required(VERSION 3.28)
#To get the right compailer for the project
#cmake -G "MinGW Makefiles" -DCMAKE_C_COMPILER="C:\\msys64\\mingw64\\bin\\gcc.exe" ..

# Set the project name and specify the language
project(Dev VERSION 1.0 LANGUAGES C)

set(CMAKE_C_COMPILER "C:\\msys64\\mingw64\\bin\\gcc.exe")

# Set the C standard to C23; New is always better
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED True)


#Add the include directory
include_directories(include)
include_directories(include\\curl)

file(GLOB SOURCES "src/*.c" "src/api/*.c")

# Specify the main executable source file
set(MAIN_EXECUTABLE_SOURCE "src/main.c")

# Remove the main executable source file from the SOURCES list
list(REMOVE_ITEM SOURCES ${MAIN_EXECUTABLE_SOURCE})

# Add the main executable with all other source files
add_executable(Dev ${MAIN_EXECUTABLE_SOURCE} ${SOURCES})


# Set the path to the CURL library and include directory
add_definitions(-DCURL_STATICLIB)
set(CURL_LIBRARY "E:/dev/project_mc/lib")
set(CURL_INCLUDE_DIR "E:/dev/project_mc/include/curl")
set(CURL_USE_STATIC_LIBS TRUE)
find_package(CURL REQUIRED)
include_directories( ${CURL_INCLUDE_DIRS} )
target_link_libraries(${PROJECT_NAME} CURL::libcurl)

#Debugging
#message("curl libs: ${CURL_LIBRARY}")
#message("curl dirs: ${CURL_INCLUDE_DIR}")
#set(CMAKE_VERBOSE_MAKEFILE ON)

#Enable testing
enable_testing()
add_test(NAME HelpFlagTest COMMAND Dev -h)
add_test(NAME YaraRuleTest COMMAND Dev -y)