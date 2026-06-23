project(vaulten_aura_test)

# TODO: Including all files involved in testing may not be the
# nicest way, Is there a different way to do it?
set(common_sources
    ${vaulten_aura_SOURCE_DIR}/lib/error_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/utils_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/memory/mem_v1.c
    ${vaulten_aura_SOURCE_DIR}/lib/memory/slab_v1.c
    ${vaulten_aura_SOURCE_DIR}/lib/memory/sliding_buf.c
)

# -------------------- DB TESTS -------------------- #
add_executable(test_aura_db
    db/basic.c
    ${vaulten_aura_SOURCE_DIR}/lib/db/db.c
    ${vaulten_aura_SOURCE_DIR}/lib/hasher_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/file/lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/encrypt/lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/string_lib.c
    ${common_sources}
)
target_link_libraries(test_aura_db PUBLIC OpenSSL::SSL OpenSSL::Crypto)
target_include_directories(test_aura_db 
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib/memory
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib
    PRIVATE ${PROJECT_INCLUDE_DIR}
)

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
    memory/slab/basic.c
    ${common_sources}
)

target_include_directories(test_aura_slab 
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib/memory
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib
    PRIVATE ${PROJECT_INCLUDE_DIR}
)

add_test(
    NAME slab_test
    COMMAND test_aura_slab
    CONFIGURATIONS Debug RelWithDebInfo ""
)

set_tests_properties(slab_test PROPERTIES
    LABELS "slab"
)

# -------------------- DAEMON TESTS -------------------- #
# System lifecycle
add_executable(test_aura_daemon
    daemon/basic.c
    ${vaulten_aura_SOURCE_DIR}/src/cli/commands/sys_cli.c
    ${vaulten_aura_SOURCE_DIR}/lib/unix/sock.c
    ${vaulten_aura_SOURCE_DIR}/lib/ipc/ipc.c
    ${common_sources}
)

target_include_directories(test_aura_daemon 
    PRIVATE ${vaulten_aura_SOURCE_DIR}/src/cli/include
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib/memory
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib
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

# Bytecode generation
add_executable(test_bytecode_gen
    daemon/codegen.c
    ${vaulten_aura_SOURCE_DIR}/lib/file/lib.c
    ${common_sources}
)

target_include_directories(test_bytecode_gen 
    PRIVATE ${vaulten_aura_SOURCE_DIR}/src/cli/include
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib/memory
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib
    PRIVATE ${PROJECT_INCLUDE_DIR}
)

target_link_libraries(test_bytecode_gen PRIVATE quickjs)

add_test(
    NAME codegen_test
    COMMAND test_bytecode_gen
    CONFIGURATIONS Debug RelWithDebInfo ""
)

set_tests_properties(codegen_test PROPERTIES
    LABELS "daemon;codegen"
    TIMEOUT 10
)

# -------------------- CLI TESTS -------------------- #
add_executable(test_aura_cli
    cli/basic.c
    ${common_sources}
)

target_include_directories(test_aura_cli 
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib/memory
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib
    PRIVATE ${PROJECT_INCLUDE_DIR}
)

add_test(
    NAME cli_test
    COMMAND test_aura_cli
    CONFIGURATIONS Debug RelWithDebInfo ""
)

set_tests_properties(cli_test PROPERTIES
    LABELS "cli"
    TIMEOUT 10
    DISABLED YES
)

# ----------------------- HEAP TEST ---------------------- #
add_executable(test_aura_heap
    heap/basic.c
    ${vaulten_aura_SOURCE_DIR}/lib/heap/lib_v1.c
    ${common_sources}
)

target_include_directories(test_aura_heap
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib/memory
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib
    PRIVATE ${PROJECT_INCLUDE_DIR}
)

add_test(
    NAME heap_test
    COMMAND test_aura_heap
    CONFIGURATIONS Debug RelWithDebInfo ""
)

set_tests_properties(heap_test PROPERTIES
    LABELS "heap"
    TIMEOUT 10
)

# ----------------------- URL LIB TEST ---------------------- #
add_executable(test_aura_url
    unit/url.c
    ${vaulten_aura_SOURCE_DIR}/lib/url/lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/string_lib.c
    ${common_sources}
)

target_include_directories(test_aura_url
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib/memory
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib
    PRIVATE ${PROJECT_INCLUDE_DIR}
)

add_test(
    NAME url_test
    COMMAND test_aura_url
    CONFIGURATIONS Debug RelWithDebInfo ""
)

set_tests_properties(url_test PROPERTIES
    LABELS "url"
    TIMEOUT 10
)

# --------------------- HASHMAP TEST ---------------------- #
add_executable(test_aura_hashmap
    hashmap/basic.c
    ${vaulten_aura_SOURCE_DIR}/lib/hashmap/map_v1.c
    ${vaulten_aura_SOURCE_DIR}/lib/hasher_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/string_lib.c
    ${common_sources}
)

target_include_directories(test_aura_hashmap
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib/memory
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib
    PRIVATE ${PROJECT_INCLUDE_DIR}
)

add_test(
    NAME hashmap_test
    COMMAND test_aura_hashmap
    CONFIGURATIONS Debug RelWithDebInfo ""
)

set_tests_properties(hashmap_test PROPERTIES
    LABELS "hashmap"
    TIMEOUT 10
)

# --------------------- HPACK_TEST --------------------- #
add_executable(test_aura_hpack
    hpack/basic.c
    ${vaulten_aura_SOURCE_DIR}/src/server/protocol/h2/hpack.c
    ${vaulten_aura_SOURCE_DIR}/src/server/protocol/h2/header.c
    ${vaulten_aura_SOURCE_DIR}/src/server/srv/interned.c
    ${vaulten_aura_SOURCE_DIR}/lib/hasher_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/string_lib.c
    ${common_sources}
)

target_link_libraries(test_aura_hpack PUBLIC OpenSSL::SSL OpenSSL::Crypto)

target_include_directories(test_aura_hpack
    PRIVATE ${vaulten_aura_SOURCE_DIR}/src/server/include
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib/memory
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib
    PRIVATE ${PROJECT_INCLUDE_DIR}
)

add_test(
    NAME hpack_test
    COMMAND test_aura_hpack
    CONFIGURATIONS Debug RelWithDebInfo ""
)

set_tests_properties(hpack_test PROPERTIES
    LABELS "hpack"
    TIMEOUT 10
)

# --------------------- QUICKJS_TEST --------------------- #
add_executable(test_aura_qjs
    js/basic.c
    ${vaulten_aura_SOURCE_DIR}/lib/file/lib.c
    ${common_sources}
)

target_link_libraries(test_aura_qjs
    PRIVATE quickjs
)

target_include_directories(test_aura_qjs
    PRIVATE ${vaulten_aura_SOURCE_DIR}/src/server/include
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib/memory
    PRIVATE ${vaulten_aura_SOURCE_DIR}/lib
    PRIVATE ${PROJECT_INCLUDE_DIR}
)

add_test(
    NAME quickjs_test
    COMMAND test_aura_qjs
    CONFIGURATIONS Debug RelWithDebInfo ""
)

set_tests_properties(quickjs_test PROPERTIES
    LABELS "quickjs"
    TIMEOUT 10
)