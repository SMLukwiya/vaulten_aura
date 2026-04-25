cmake_minimum_required(VERSION 3.31.5)
list(APPEND CMAKE_MESSAGE_CONTEXT vaulten_aura)
project(vaulten_aura VERSION 1.0.0)

find_package(OpenSSL REQUIRED)

find_package(ZLIB REQUIRED)

find_package(Threads REQUIRED)

option(BUILD_SHARED_LIBS "Build a shared library" OFF)

if (OPENSSL_VERSION VERSION_LESS "3.0.0")
    message(FATAL_ERROR
        "   OpenSSL 3.0.0 is the minimum supported version"
    )
endif()

#test
enable_testing()

include(cmake/dependencies.cmake)

set(PROJECT_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)

add_compile_definitions(_GNU_SOURCE)
# Default Paths
set(DEFAULT_DATA_DIR /var/lib/vaulten_aura CACHE PATH "Default data directory")

add_compile_definitions(AURA_APP_NAME="vaulten_aura")
add_compile_definitions(AURA_DB_FILE="aura.db")
add_compile_definitions(AURA_DB_WAL_FILE="aura_db.wal")
add_compile_definitions(AURA_DB_COMPACT_FILE="aura_compact.db")

add_subdirectory(tests)
add_subdirectory(src/cli)
add_subdirectory(src/daemon)
add_subdirectory(src/server)

set(CMAKE_C_FLAGS_DEBUG "-O0")
set(CMAKE_C_FLAGS_RELEASE "-O2")

# installation
set(install_dir ${PROJECT_BINARY_DIR}/install)

# packaging
include(GNUInstallDirs)
install(
    TARGETS aura aura_daemon
)
