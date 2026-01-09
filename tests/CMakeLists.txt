project(vaulten_aura_test)

# TODO: Including all files involved in testing may not be the
# nicest way, Is there a different way to do it?
set(common_sources
    ${vaulten_aura_SOURCE_DIR}/lib/error_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/utils_lib.c
)

# -------------------- DB TESTS -------------------- #
add_executable(test_aura_db
    db/basic.c
    ${vaulten_aura_SOURCE_DIR}/lib/db/db.c
    ${vaulten_aura_SOURCE_DIR}/lib/hash_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/file_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/encrypt_lib.c
    ${common_sources}
)

target_link_libraries(test_aura_db PUBLIC openssl::openssl)
target_include_directories(test_aura_db PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include PRIVATE ${PROJECT_INCLUDE_DIR})

add_test(
    NAME db_test
    COMMAND test_aura_db
    CONFIGURATIONS Debug RelWithDebInfo ""
)

set_tests_properties(db_test PROPERTIES
    LABELS "db"
)

# -------------------- SLAB TESTS -------------------- #
add_executable(test_aura_slab
    slab/basic.c
    ${vaulten_aura_SOURCE_DIR}/lib/slab_lib_v1.c
    ${common_sources}
)

target_include_directories(test_aura_slab PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include PRIVATE ${PROJECT_INCLUDE_DIR})

add_test(
    NAME slab_test
    COMMAND test_aura_slab
    CONFIGURATIONS Debug RelWithDebInfo ""
)

set_tests_properties(db_test PROPERTIES
    LABELS "slab"
)

# -------------------- DAEMON TESTS -------------------- #
add_executable(test_aura_daemon
    daemon/basic.c
    ${vaulten_aura_SOURCE_DIR}/src/cli/src/commands/system_cli.c
    ${vaulten_aura_SOURCE_DIR}/lib/unix_socket_lib.c
    ${common_sources}
)

target_include_directories(test_aura_daemon 
    PRIVATE ${vaulten_aura_SOURCE_DIR}/src/cli/include
    PRIVATE ${PROJECT_INCLUDE_DIR}
)

message(STATUS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
add_test(
    NAME daemon_test
    COMMAND test_aura_daemon
    CONFIGURATIONS Debug RelWithDebInfo ""
)

set_tests_properties(daemon_test PROPERTIES
    LABELS "daemon"
    TIMEOUT 10
)

# -------------------- CLI TESTS -------------------- #
add_executable(test_aura_cli
    cli/basic.c
    ${common_sources}
)

target_include_directories(test_aura_cli PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include PRIVATE ${PROJECT_INCLUDE_DIR})

message(STATUS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
add_test(
    NAME cli_test
    COMMAND test_aura_cli
    CONFIGURATIONS Debug RelWithDebInfo ""
)

set_tests_properties(cli_test PROPERTIES
    LABELS "cli"
    TIMEOUT 10
)