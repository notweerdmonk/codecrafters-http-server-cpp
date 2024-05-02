cmake_minimum_required(VERSION 3.13)
project(http-server-starter-cpp)
set(CMAKE_CXX_STANDARD 20) # Enable the C++20 standard

set(SOURCE_FILES src/server.cpp)

add_executable(server ${SOURCE_FILES})
add_executable(test_server tests/test_server.cpp)

target_link_libraries(server pthread)
target_link_libraries(test_server curl)
target_link_libraries(test_server pthread)
