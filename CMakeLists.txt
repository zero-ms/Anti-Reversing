cmake_minimum_required(VERSION 3.21)
project(CheckSecurity)

set(CMAKE_CXX_STANDARD 17)

add_executable(CheckSecurity main.cpp)
target_link_libraries(CheckSecurity Shlwapi.lib)
