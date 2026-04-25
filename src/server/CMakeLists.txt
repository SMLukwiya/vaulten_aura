list(APPEND CMAKE_MESSAGE_CONTEXT server)

message(STATUS "Building server")
list(APPEND CMAKE_MESSAGE_INDENT " ")

set(lib_sources
    ${vaulten_aura_SOURCE_DIR}/lib/unix_socket_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/error_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/privilege_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/utils_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/blobber_v1_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/radix_v1_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/memory_lib_v1.c
    ${vaulten_aura_SOURCE_DIR}/lib/slab_lib_v1.c
    ${vaulten_aura_SOURCE_DIR}/lib/hasher_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/db/db.c
    ${vaulten_aura_SOURCE_DIR}/lib/db/db_broker.c
    ${vaulten_aura_SOURCE_DIR}/lib/file_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/encrypt_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/ipc_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/function_v1_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/heap_lib_v1.c
    ${vaulten_aura_SOURCE_DIR}/lib/string_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/url_lib.c
)

add_executable(aura_server 
    # src/main.c
    main.c
    net/socket_srv.c
    net/epoll_srv.c
    net/tls_srv.c
    srv/evt_loop_srv.c
    srv/route_srv.c
    srv/interned.c
    protocol/connection.c
    protocol/h2/header_srv.c
    protocol/h2/session.c
    protocol/h2/h2_srv.c
    protocol/h2/h2_cli.c
    protocol/h2/frame.c
    protocol/h2/stream.c
    protocol/h2/hpack_srv.c
    protocol/h2/scheduler.c
    runtime/worker_man.c
    runtime/runtime.c
    runtime/request.c
    runtime/task.c
    runtime/quickjs/qjs_rt.c
    runtime/quickjs/js_bindings.c 
    infra/timer/timer_srv.c
    src/optimization_srv.c

    ${lib_sources}
)

target_link_libraries(aura_server 
    PRIVATE picotls-openssl picotls-fusion picotls-minicrypto picotls-core 
    PRIVATE quickjs 
    PUBLIC OpenSSL::SSL OpenSSL::Crypto
)

target_include_directories(aura_server 
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include 
    PRIVATE ${PROJECT_INCLUDE_DIR}
)

target_compile_definitions(aura_server 
    PRIVATE AURA_DATA_DIR="${DEFAULT_DATA_DIR}" # defined in global CMakeLists.txt
)

list(POP_BACK CMAKE_MESSAGE_INDENT)
