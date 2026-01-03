cmake_minimum_required(VERSION 3.31.5)
list(APPEND CMAKE_MESSAGE_CONTEXT vaulten_aura)
project(vaulten_aura VERSION 1.0.0)

find_package(OpenSSL REQUIRED)

find_package(quickjs REQUIRED)

find_package(wasmtime REQUIRED)

find_package(picotls REQUIRED)

find_package(yaml REQUIRED)

# find_package(CURL REQUIRED)
# target_link_libraries(target CURL::libcurl)

set(PROJECT_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)

# todo: find a better way
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
endif()

add_compile_definitions(_GNU_SOURCE)
# Default Paths
set(DEFAULT_DATA_DIR /var/lib/vaulten_aura CACHE PATH "Default data directory")

add_compile_definitions(AURA_APP_NAME="vaulten_aura")
add_compile_definitions(AURA_DB_FILE="aura.db")
add_compile_definitions(AURA_DB_COMPACT_FILE="aura_compact.db")

add_subdirectory(src/cli)
add_subdirectory(src/daemon)
add_subdirectory(src/server)

# installation
set(install_dir ${PROJECT_BINARY_DIR}/install)

# packaging
include(GNUInstallDirs)
install(
    TARGETS aura aura_daemon
)


# cmake --preset conan-release