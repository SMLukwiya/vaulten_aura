cmake_minimum_required(VERSION 3.31.5)
project(vaulten_aura VERSION 1.0.0)

find_package(OpenSSL REQUIRED)

find_package(quickjs REQUIRED)

find_package(wasmtime REQUIRED)

find_package(picotls REQUIRED)

find_package(yaml REQUIRED)

# find_package(CURL REQUIRED)
# target_link_libraries(target CURL::libcurl)

set(PROJECT_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
# set(PROJECT_LIB_DIR ${CMAKE_BINARY_DIR}/lib)

# todo: find a better way
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
endif()

add_subdirectory(src/cli)
add_subdirectory(src/daemon)
add_subdirectory(src/server)

# installation
set(install_dir ${PROJECT_BINARY_DIR}/install)

# compile flags

# if (BUILD_TESTING)
#     add_subdirectory(test)
# endif()

# target_link_libraries(vaulten_aura cli daemon)

# target_sources()

# packaging
include(GNUInstallDirs)
install(
    TARGETS aura aura_daemon
)


# cmake --preset conan-release