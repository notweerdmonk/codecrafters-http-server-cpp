cmake_minimum_required(VERSION 3.13)
project(http-server-starter-cpp)
set(CMAKE_CXX_STANDARD 20) # Enable the C++20 standard

set(SOURCE_FILES src/server.cpp)

add_executable(server ${SOURCE_FILES})

target_link_libraries(server PRIVATE pthread)

option(OFFLINE_TESTS "Enable offline tests" OFF)

if(OFFLINE_TESTS)
  add_executable(test_server tests/test_server.cpp)

  target_link_libraries(test_server PRIVATE curl)
  target_link_libraries(test_server PRIVATE pthread)

  add_executable(test_re tests/test_re.cc)
endif()

