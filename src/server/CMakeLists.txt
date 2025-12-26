set(lib_sources
    ../../lib/unix_socket_lib.c
    ../../lib/error_lib.c
    ../../lib/privilege_lib.c
    ../../lib/utils_lib.c
    ../../lib/blobber_v1_lib.c
    ../../lib/radix_v1_lib.c
    ../../lib/memory_lib_v1.c
    ../../lib/slab_lib_v1.c
    ../../lib/runtime_lib.c
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

# if (it bsd)
# target_sources(aura_server path_to_kevent)
# else() #if linux
# target_sources(aura_server path_to_epoll)
# endif() # if apple etc

target_link_libraries(aura_server PRIVATE picotls::picotls PRIVATE quickjs::quickjs PUBLIC openssl::openssl)

target_include_directories(aura_server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include PRIVATE ${PROJECT_INCLUDE_DIR})

add_compile_definitions(_GNU_SOURCE)

# todo: find a better way
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    # set(CMAKE_STATIC_LINKER_FLAGS "")
endif()

# if (UNIX AND NOT APPLE)
#     target_compile_definitions(aura_daemon PRIVATE HAS_SYSTEMD) # or another manager
# # else others
# endif()