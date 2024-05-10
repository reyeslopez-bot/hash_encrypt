cmake_minimum_required(VERSION 3.10)
project(LatticeCrypto)

set(CMAKE_CXX_STANDARD 17)

# Eigen
include_directories(/opt/homebrew/Cellar/eigen/3.4.0_1/include/eigen3)

add_executable(LatticeCrypto lattice_crypto.cpp)
