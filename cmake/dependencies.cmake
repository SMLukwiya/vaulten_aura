# Quickjs
set(QUICKJS_SOURCE_FILES
    ${PROJECT_SOURCE_DIR}/deps/quickjs/cutils.c
    ${PROJECT_SOURCE_DIR}/deps/quickjs/dtoa.c
    ${PROJECT_SOURCE_DIR}/deps/quickjs/libregexp.c
    ${PROJECT_SOURCE_DIR}/deps/quickjs/libunicode.c
    ${PROJECT_SOURCE_DIR}/deps/quickjs/qjs.c
    ${PROJECT_SOURCE_DIR}/deps/quickjs/qjsc.c
    ${PROJECT_SOURCE_DIR}/deps/quickjs/quickjs-libc.c
    ${PROJECT_SOURCE_DIR}/deps/quickjs/quickjs.c
    ${PROJECT_SOURCE_DIR}/deps/quickjs/unicode_gen.c
)

add_library(quickjs
    STATIC
    EXCLUDE_FROM_ALL
    ${QUICKJS_SOURCE_FILES}
)

file(READ "${PROJECT_SOURCE_DIR}/deps/quickjs/VERSION" QUICKJS_VERSION)
string(STRIP "${QUICKJS_VERSION}" QUICKJS_VERSION)

target_compile_definitions(quickjs
    PRIVATE CONFIG_VERSION="${QUICKJS_VERSION}"
)

target_include_directories(quickjs
    PUBLIC ${PROJECT_SOURCE_DIR}/deps/quickjs
    
)

target_link_libraries(quickjs PUBLIC m)

# Picotls
add_subdirectory(${PROJECT_SOURCE_DIR}/deps/picotls
    EXCLUDE_FROM_ALL
)

# Libyaml
add_subdirectory(${PROJECT_SOURCE_DIR}/deps/libyaml
    EXCLUDE_FROM_ALL
)

include_directories(
    deps/picotls/include
    deps/picotest
    deps/picotls/deps/cifra/src/ext
    deps/picotls/deps/cifra/src
    deps/picotls/deps/micro-ecc
)
