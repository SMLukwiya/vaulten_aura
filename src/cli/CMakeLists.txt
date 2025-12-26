# @todo: should I call project()?

# find_package(libyaml REQUIRED)

set(lib_sources
    ../../lib/unix_socket_lib.c
    ../../lib/string_lib.c
    ../../lib/error_lib.c
    ../../lib/file_lib.c
    ../../lib/yaml_lib.c # remove this not needed here
    ../../lib/radix_v1_lib.c # remove this not needed as well
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

# install(TARGETS cli RUNTIME DESTINATION bin)

