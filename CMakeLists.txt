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

if (APP_DEV_BUILD)
    message(INFO, "  DEV BUILD")
endif()

include(cmake/dependencies.cmake)

set(PROJECT_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)

add_compile_definitions(_GNU_SOURCE)

add_compile_definitions(AURA_APP_NAME="vaulten_aura")
add_compile_definitions(AURA_DB_FILE="aura.db")
add_compile_definitions(AURA_DB_WAL_FILE="aura_db.wal")
add_compile_definitions(AURA_DB_COMPACT_FILE="aura_compact.db")

if (APP_DEV_BUILD)
    add_compile_definitions(AURA_DEV_BUILD="ON")
endif()

if (BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

add_subdirectory(src/cli)
add_subdirectory(src/daemon)
add_subdirectory(src/server)

set(CMAKE_C_FLAGS_DEBUG "-O0 -g")
set(CMAKE_C_FLAGS_RELEASE "-O2")

# installation
set(install_dir ${PROJECT_BINARY_DIR}/install)

# packaging
include(GNUInstallDirs)
install(
    TARGETS aura aura_daemon aura_server
    COMPONENT runtime
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(
    FILES ${PROJECT_SOURCE_DIR}/conf.yaml
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/${PROJECT_NAME}
    COMPONENT config
)

if (NOT DEFINED SYSTEMD_UNITDIR OR "${SYSTEMD_UNITDIR}" STREQUAL "")
    if (CMAKE_INSTALL_PREFIX STREQUAL "/usr" OR CMAKE_INSTALL_PREFIX STREQUAL "/")
        set (SYSTEMD_UNITDIR "/lib/systemd/system")
    else()
        set(SYSTEMD_UNITDIR "${CMAKE_INSTALL_PREFIX}/lib/systemd/system")
    endif()
endif()

configure_file(
    ${PROJECT_SOURCE_DIR}/systemd/v_aura.service.in
    ${CMAKE_CURRENT_BINARY_DIR}/v_aura.service
    @ONLY
)

install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/v_aura.service
    DESTINATION ${SYSTEMD_UNITDIR}
    COMPONENT systemd
)
