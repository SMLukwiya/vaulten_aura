list(APPEND CMAKE_MESSAGE_CONTEXT cli)
# project(aura_cli VERSION 1.0.0)

message(STATUS "Building cli")
list(APPEND CMAKE_MESSAGE_INDENT " ")

set(lib_sources
    ${vaulten_aura_SOURCE_DIR}/lib/unix/sock.c
    ${vaulten_aura_SOURCE_DIR}/lib/error_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/file/lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/utils_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/memory/mem_v1.c
    ${vaulten_aura_SOURCE_DIR}/lib/memory/slab_v1.c
    ${vaulten_aura_SOURCE_DIR}/lib/ipc/ipc.c
)

add_executable(aura 
    main.c
    cmdline.c
    commands/function/cli.c
    commands/function/deploy.c
    commands/function/delete.c
    commands/function/status.c
    commands/function/start.c
    commands/function/stop.c
    commands/function/validate_conf.c
    commands/function/list.c
    commands/sys_cli.c
    commands/server/cli.c
    commands/server/validate_conf.c
    commands/server/start.c
    commands/server/stop.c
    commands/server/status.c
    commands/root_cli.c
    flag.c
    ${lib_sources}
)

target_link_libraries(aura PRIVATE yaml)

target_include_directories(aura
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib/memory
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib
    PRIVATE ${PROJECT_INCLUDE_DIR}
)

list(POP_BACK CMAKE_MESSAGE_INDENT)
