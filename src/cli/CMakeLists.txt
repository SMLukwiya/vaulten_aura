list(APPEND CMAKE_MESSAGE_CONTEXT cli)
# project(aura_cli VERSION 1.0.0)

message(STATUS "Building cli")
list(APPEND CMAKE_MESSAGE_INDENT " ")

set(lib_sources
    ${vaulten_aura_SOURCE_DIR}/lib/unix_socket_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/string_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/error_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/file_lib.c
)

add_executable(aura 
    src/main.c
    src/cmdline_cli.c
    src/commands/help_cli.c
    src/commands/function_cli.c
    src/commands/fn_delete_cli.c
    src/commands/fn_deploy_cli.c
    src/commands/fn_config_validate_cli.c
    src/commands/srv_config_validate_cli.c
    src/commands/srv_start_cli.c
    src/commands/srv_stop_cli.c
    src/commands/srv_status_cli.c
    src/commands/system_cli.c
    src/commands/server_cli.c
    src/flag_cli.c
    ${lib_sources}
)

target_link_libraries(aura PRIVATE yaml::yaml)

target_include_directories(aura PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include PRIVATE ${PROJECT_INCLUDE_DIR})

list(POP_BACK CMAKE_MESSAGE_INDENT)

# install(TARGETS cli RUNTIME DESTINATION bin)

