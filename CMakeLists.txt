cmake_minimum_required(VERSION 3.13)
project(http-server-starter-cpp)
set(CMAKE_CXX_STANDARD 20) # Enable the C++20 standard

set(SOURCE_FILES src/server.cpp)
set(INCLUDE_DIR src)

find_package(ZLIB REQUIRED)

add_executable(server ${SOURCE_FILES})

target_include_directories(server PRIVATE ${INCLUDE_DIR})

target_link_libraries(server PRIVATE pthread)
target_link_libraries(server PRIVATE ZLIB::ZLIB)

option(OFFLINE_TESTS "Enable offline tests" OFF)

if(OFFLINE_TESTS)
  add_executable(test_server tests/test_server.cpp)

  target_link_libraries(test_server PRIVATE curl)
  target_link_libraries(test_server PRIVATE pthread)

  add_executable(test_re tests/test_re.cc)

  add_executable(test_zlib tests/test_zlib.cc)

  target_link_libraries(test_zlib PRIVATE ZLIB::ZLIB)
endif()

