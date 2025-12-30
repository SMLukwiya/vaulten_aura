
# Daemon library sources
set(lib_sources
    ../../lib/unix_socket_lib.c
    ../../lib/daemon_lib.c
    ../../lib/error_lib.c
    ../../lib/file_lib.c
    ../../lib/yaml_lib.c
    ../../lib/utils_lib.c
    ../../lib/radix_v1_lib.c
    ../../lib/blobber_v1_lib.c
    ../../lib/encrypt_lib.c
    ../../lib/ipc_lib.c
    ../../lib/hash_lib.c
    ../../lib/db/db.c
    ../../lib/file_lib.c
    ../../lib/runtime_lib.c # remove this once I have a good place to put runtime stuff
)

# Default Paths
set(DEFAULT_DATA_DIR /var/lib/vaulten_aura CACHE PATH "Default data directory")
# set(DEFAULT_FUNCTION_DIR function CACHE PATH "Default function directory")

add_executable(aura_daemon
    src/main.c
    src/aura_dmn.c
    src/command/common_dmn.c
    src/command/svr_start_dmn.c
    src/command/srv_config_validate_dmn.c
    src/command/fn_config_validate_dmn.c
    src/command/fn_deploy_dmn.c
    ${lib_sources}
)

target_link_libraries(aura_daemon PUBLIC openssl::openssl PRIVATE picotls::picotls PRIVATE)
target_link_libraries(aura_daemon PRIVATE quickjs::quickjs PRIVATE wasmtime::wasmtime PRIVATE yaml::yaml)

target_include_directories(aura_daemon PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include PRIVATE ${PROJECT_INCLUDE_DIR})

add_compile_definitions(_GNU_SOURCE)
add_compile_definitions(AURA_APP_NAME="vaulten_aura")
add_compile_definitions(AURA_DB_FILE="aura.db")
target_compile_definitions(aura_daemon 
    PRIVATE AURA_DATA_DIR="${DEFAULT_DATA_DIR}"
    # PRIVATE AURA_FN_DIR="${DEFAULT_FUNCTION_DIR}"
)
