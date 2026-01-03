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
    ${vaulten_aura_SOURCE_DIR}/lib/hash_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/db/db.c
    ${vaulten_aura_SOURCE_DIR}/lib/file_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/encrypt_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/runtime_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/ipc_lib.c
)

add_executable(aura_server 
    src/main.c
    src/socket_srv.c
    src/evt_loop_srv.c
    src/epoll_srv.c
    src/header_srv.c
    src/h2/h2_srv.c
    src/h2/frame.c
    src/h2/stream.c
    src/h2/connection.c
    src/h2/hpack_srv.c
    src/h2/scheduler.c
    src/route_srv.c
    exec/workers/worker_man.c # not sure where this belongs for now
    exec/runtime/quickjs/qjs_rt.c #not sure where this belongs for now
    exec/runtime/quickjs/js_bindings.c 

    ${lib_sources}
)

target_link_libraries(aura_server PRIVATE picotls::picotls PRIVATE quickjs::quickjs PUBLIC openssl::openssl)

target_include_directories(aura_server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include PRIVATE ${PROJECT_INCLUDE_DIR})

target_compile_definitions(aura_server 
    PRIVATE AURA_DATA_DIR="${DEFAULT_DATA_DIR}" # defined in global CMakeLists.txt
)

list(POP_BACK CMAKE_MESSAGE_INDENT)
