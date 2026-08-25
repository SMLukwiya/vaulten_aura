list(APPEND CMAKE_MESSAGE_CONTEXT daemon)

message(STATUS "Building daemon")
list(APPEND CMAKE_MESSAGE_INDENT " ")

# Daemon library sources
set(lib_sources
    ${vaulten_aura_SOURCE_DIR}/lib/unix/sock.c
    ${vaulten_aura_SOURCE_DIR}/lib/daemon_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/error_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/yaml/lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/utils_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/radix/tree_v1.c
    ${vaulten_aura_SOURCE_DIR}/lib/blobber/lib_v1.c
    ${vaulten_aura_SOURCE_DIR}/lib/encrypt/lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/hasher_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/hashmap/map_v1.c
    ${vaulten_aura_SOURCE_DIR}/lib/db/db.c
    ${vaulten_aura_SOURCE_DIR}/lib/db/broker.c
    ${vaulten_aura_SOURCE_DIR}/lib/file/lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/fn/lib_v1.c
    ${vaulten_aura_SOURCE_DIR}/lib/memory/mem_v1.c
    ${vaulten_aura_SOURCE_DIR}/lib/memory/slab_v1.c
    ${vaulten_aura_SOURCE_DIR}/lib/memory/sliding_buf.c
    ${vaulten_aura_SOURCE_DIR}/lib/string_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/user/user.c
    ${vaulten_aura_SOURCE_DIR}/lib/ipc/ipc.c
    ${vaulten_aura_SOURCE_DIR}/lib/ipc/wait.c
    ${vaulten_aura_SOURCE_DIR}/lib/event_ctx/http.c
    ${vaulten_aura_SOURCE_DIR}/lib/event_ctx/cron.c
    ${vaulten_aura_SOURCE_DIR}/lib/cron/ccronexpr.c
    ${vaulten_aura_SOURCE_DIR}/lib/memory/lru_cache.c
    ${vaulten_aura_SOURCE_DIR}/lib/timer/timer.c
    ${vaulten_aura_SOURCE_DIR}/lib/stream/lib_v1.c
    ${vaulten_aura_SOURCE_DIR}/lib/event_ctx/context.c
    ${vaulten_aura_SOURCE_DIR}/lib/event_ctx/http.c
    ${vaulten_aura_SOURCE_DIR}/lib/event_ctx/cron.c
)

add_executable(aura_daemon
    main.c
    command/common_dmn.c
    command/server/start.c
    command/server/stop.c
    command/server/status.c
    command/server/stop.c
    command/server/validate_conf.c
    command/function/validate_conf.c
    command/function/deploy.c
    command/function/delete.c
    command/function/status.c
    command/function/list.c
    command/system.c
    db/broker.c
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
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib/memory
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib
    PRIVATE ${PROJECT_INCLUDE_DIR}
)

target_compile_definitions(aura_daemon 
    PRIVATE AURA_DATA_DIR="${DEFAULT_DATA_DIR}" # defined in global CMakeLists.txt
)

list(POP_BACK CMAKE_MESSAGE_INDENT)
