cmake_minimum_required(VERSION 3.10)
project(LatticeCrypto)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set the build type if it is not already set
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

# Sanitizer options
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address")
set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fsanitize=address")

# Set the macOS SDK path
execute_process(COMMAND xcrun --show-sdk-path OUTPUT_VARIABLE MACOSX_SDK_PATH OUTPUT_STRIP_TRAILING_WHITESPACE)
set(CMAKE_OSX_SYSROOT ${MACOSX_SDK_PATH})

# Find required packages
find_package(Threads REQUIRED)
find_package(Boost REQUIRED COMPONENTS system thread)
find_package(Eigen3 REQUIRED NO_MODULE)

# Include directories
include_directories(${Boost_INCLUDE_DIRS})
include_directories(${EIGEN3_INCLUDE_DIR})

# Define the executable
add_executable(LatticeCrypto lattice_crypto.cpp)

# Link libraries to the executable
target_link_libraries(LatticeCrypto ${Boost_LIBRARIES} Eigen3::Eigen Threads::Threads)

# Ensure runtime directory is correctly set
set_target_properties(LatticeCrypto PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

# Custom target to run the program and filter output for 'ERROR'
add_custom_target(run_with_filter
    COMMAND ${CMAKE_BINARY_DIR}/LatticeCrypto | grep "ERROR" || true
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running LatticeCrypto and filtering output for 'ERROR'"
    DEPENDS LatticeCrypto
)
