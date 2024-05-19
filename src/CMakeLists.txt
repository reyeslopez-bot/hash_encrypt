cmake_minimum_required(VERSION 3.10)
project(LatticeCrypto)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
set(CMAKE_BUILD_TYPE Debug)
# Include the directory where Eigen headers are located
include_directories("/opt/homebrew/include/eigen3")

add_executable(LatticeCrypto lattice_crypto.cpp)
