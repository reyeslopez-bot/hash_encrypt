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
find_package(Boost REQUIRED COMPONENTS system thread)
find_package(Eigen3 REQUIRED NO_MODULE)

# Now find the threading library
set(CMAKE_THREAD_LIBS_INIT "-lpthread")
set(CMAKE_HAVE_THREADS_LIBRARY 1)
set(CMAKE_USE_WIN32_THREADS_INIT 0)
set(CMAKE_USE_PTHREADS_INIT 1)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
if(THREADS_HAVE_PTHREAD_ARG)
  set_property(TARGET my_target PROPERTY COMPILE_OPTIONS "-pthread")
  set_property(TARGET my_target PROPERTY INTERFACE_COMPILE_OPTIONS "-pthread")
endif()


# Include directories
include_directories(${Boost_INCLUDE_DIRS})
include_directories(${EIGEN3_INCLUDE_DIR})

# Define the executable
add_executable(LatticeCrypto lattice_crypto.cpp)

# Link libraries to the executable, including the Threads library
target_link_libraries(LatticeCrypto ${Boost_LIBRARIES} Eigen3::Eigen Threads::Threads)
