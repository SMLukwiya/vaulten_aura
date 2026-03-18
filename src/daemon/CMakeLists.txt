list(APPEND CMAKE_MESSAGE_CONTEXT daemon)

message(STATUS "Building daemon")
list(APPEND CMAKE_MESSAGE_INDENT " ")

# Daemon library sources
set(lib_sources
    ${vaulten_aura_SOURCE_DIR}/lib/unix_socket_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/daemon_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/error_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/file_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/yaml_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/utils_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/radix_v1_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/blobber_v1_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/encrypt_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/ipc_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/hash_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/db/db.c
    ${vaulten_aura_SOURCE_DIR}/lib/db/db_broker.c
    ${vaulten_aura_SOURCE_DIR}/lib/file_lib.c
    # ${vaulten_aura_SOURCE_DIR}/lib/runtime_lib.c # remove this once I have a good place to put quickjs and other runtime stuff
    ${vaulten_aura_SOURCE_DIR}/lib/function_v1_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/memory_lib_v1.c
    ${vaulten_aura_SOURCE_DIR}/lib/slab_lib_v1.c
)

add_executable(aura_daemon
    src/main.c
    src/aura_dmn.c
    src/command/common_dmn.c
    src/command/srv_start_dmn.c
    src/command/srv_config_validate_dmn.c
    src/command/fn_config_validate_dmn.c
    src/command/fn_deploy_dmn.c
    src/command/fn_delete_dmn.c
    src/command/fn_status_dmn.c
    src/command/fn_list_dmn.c
    src/command/sys_dmn.c
    src/db_broker.c
    ${lib_sources}
)

target_link_libraries(aura_daemon 
    PUBLIC OpenSSL::SSL OpenSSL::Crypto 
    PRIVATE picotls-openssl picotls-fusion picotls-minicrypto picotls-core
)

target_link_libraries(aura_daemon 
    PRIVATE quickjs 
    PRIVATE yaml
)

target_include_directories(aura_daemon
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${PROJECT_INCLUDE_DIR}
)

target_compile_definitions(aura_daemon 
    PRIVATE AURA_DATA_DIR="${DEFAULT_DATA_DIR}" # defined in global CMakeLists.txt
)

list(POP_BACK CMAKE_MESSAGE_INDENT)
