cmake_minimum_required(VERSION 3.21)
project(OpenValifyCli LANGUAGES CXX)

# Require C++23
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find Boost with ProgramOptions
find_package(Boost REQUIRED COMPONENTS program_options)

# Define the executable
add_executable(OpenValifyCli main.cpp)

# Link against Boost and OpenValify
target_link_libraries(OpenValifyCli
    PRIVATE
    Boost::program_options
    OpenValify  # Assume OpenValify is defined in the root CMakeLists.txt
    $<$<BOOL:${USE_LOGFAULT}>:logfault>
)

# Installation rules
install(TARGETS OpenValifyCli
    RUNTIME DESTINATION bin
)
