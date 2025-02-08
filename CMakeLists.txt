cmake_minimum_required(VERSION 3.21)
project(OpenValify
    VERSION 0.0.1
    LANGUAGES CXX
)

# CMake options
option(OPENVALIFY_BUILD_TESTS "Build tests" OFF)
option(OPENVALIFY_BUILD_EXAMPLES "Build examples" OFF)
option(OPENVALIFY_USE_STATIC_BOOST "Link Boost statically" OFF)

## Todo [jgaa] Add a generic way to use alternative loggers
#option(USE_LOGFAULT "Enable usage of logfault for logging" ON)
set(USE_LOGFAULT ON)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if (NOT DEFINED OV_VERSION)
    set(OV_VERSION ${CMAKE_PROJECT_VERSION})
endif()
add_definitions(-DOV_VERSION=\"${OV_VERSION}\")

# Find dependencies
find_package(Boost ${USE_BOOST_VERSION} REQUIRED MODULE COMPONENTS
    system
    program_options
    )

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

include(FetchContent)

option(USE_LOGFAULT "Enable usage of logfault for logging" ON)

if (USE_LOGFAULT)
    if (TARGET logfault)
        message(STATUS "Using existing logfault target")
    else()
        if (LOGFAULT_ROOT)
            # If LOGFAULT_ROOT is set, assume it points to an existing installation
            message(STATUS "Using LOGFAULT_ROOT: ${LOGFAULT_ROOT}")
            set(LOGFAULT_DIR ${LOGFAULT_ROOT})
            include_directories(${LOGFAULT_DIR})
        else()
            # Try to find an installed logfault
            find_path(LOGFAULT_DIR NAMES logfault.h PATH_SUFFIXES logfault)

            if (NOT LOGFAULT_DIR STREQUAL "LOGFAULT_DIR-NOTFOUND")
                message(STATUS "Using existing logfault at: ${LOGFAULT_DIR}")
                add_library(logfault INTERFACE IMPORTED)
                target_include_directories(logfault INTERFACE ${LOGFAULT_DIR})
            else()
                message(STATUS "Downloading and embedding logfault (header-only)")

                FetchContent_Declare(
                    logfault
                    GIT_REPOSITORY "https://github.com/jgaa/logfault.git"
                    GIT_TAG "master"
                )
                FetchContent_MakeAvailable(logfault)
            endif()
        endif()
    endif()
endif()

# Define the library
add_library(OpenValify)
add_library(OpenValify::OpenValify ALIAS OpenValify)

# Library sources and includes
target_sources(OpenValify PRIVATE
    include/openvalify/OpenValify.h
    include/openvalify/logging.h
    src/lib/OpenValify.cpp
)

target_include_directories(OpenValify PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Link dependencies
target_link_libraries(OpenValify
    PUBLIC
    Boost::system
    #Boost::asio
    #Boost::program_options
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
    $<$<BOOL:${USE_LOGFAULT}>:logfault>
)

# Optionally link Boost statically
if(OPENVALIFY_USE_STATIC_BOOST)
    set_target_properties(OpenValify PROPERTIES
        INTERFACE_LINK_LIBRARIES "${Boost_LIBRARIES};-static"
    )
endif()

# Install library
install(TARGETS OpenValify
    EXPORT OpenValifyTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/ DESTINATION include)

# Install CMake config files
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/OpenValifyConfigVersion.cmake
    COMPATIBILITY SameMajorVersion
)

add_subdirectory(src/OpenValifyCli)

install(EXPORT OpenValifyTargets
    FILE OpenValifyTargets.cmake
    NAMESPACE OpenValify::
    DESTINATION lib/cmake/OpenValify
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/OpenValifyConfigVersion.cmake
    DESTINATION lib/cmake/OpenValify
)

# Examples
if(OPENVALIFY_BUILD_EXAMPLES)
    add_executable(example1 examples/example1.cpp)
    target_link_libraries(example1 OpenValify)

    install(TARGETS example1 DESTINATION bin)
endif()

# Tests
if(OPENVALIFY_BUILD_TESTS)
    enable_testing()
    add_executable(test_runner tests/test_main.cpp)
    target_link_libraries(test_runner OpenValify)

    add_test(NAME RunTests COMMAND test_runner)
endif()
