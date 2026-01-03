project(vaulten_aura_test)

# TODO: Including all files involved in testing is definitely not going to
# be nice, Is there a different way to do it?
set(common_sources
    ${vaulten_aura_SOURCE_DIR}/lib/error_lib.c
    ${vaulten_aura_SOURCE_DIR}/lib/utils_lib.c
)

add_executable(test_aura_db
    db/test_db.c
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
    COMMAND test_aura_db  # $<$<CONFIG:Debug>:-g>
    CONFIGURATIONS Debug RelWithDebInfo ""
)

set_tests_properties(db_test PROPERTIES
    LABELS "db"
)
