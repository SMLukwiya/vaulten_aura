# Disable test for third party libraries
set(OLD_BUILD_TESTING ${BUILD_TESTING})
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)

# Quickjs
set(QUICKJS_SOURCE_FILES
    ${PROJECT_SOURCE_DIR}/deps/quickjs/cutils.c
    ${PROJECT_SOURCE_DIR}/deps/quickjs/dtoa.c
    ${PROJECT_SOURCE_DIR}/deps/quickjs/libregexp.c
    ${PROJECT_SOURCE_DIR}/deps/quickjs/libunicode.c
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

# Link math lib to quickjs
target_link_libraries(quickjs PUBLIC m)

# Picotls
add_subdirectory(${PROJECT_SOURCE_DIR}/deps/picotls
    EXCLUDE_FROM_ALL
)

include_directories(
    deps/picotls/include
    deps/picotest
    deps/picotls/deps/cifra/src/ext
    deps/picotls/deps/cifra/src
    deps/picotls/deps/micro-ecc
)

# Libyaml
# Libyaml fails to build for it's current version < 3
# so we replace it with 3.10
function(patch_libyaml_cmake)
    set(LIBYAML_CMAKELISTS_FILE "${PROJECT_SOURCE_DIR}/deps/libyaml/CMakeLists.txt")

    if(EXISTS "${LIBYAML_CMAKELISTS_FILE}")
        file(READ "${LIBYAML_CMAKELISTS_FILE}" contents)

        if(contents MATCHES "cmake_minimum_required\\(VERSION ([0-9]+(\\.[0-9]+)?)")
            set(CURRENT_VERSION "${CMAKE_MATCH_1}")
            
            if(CURRENT_VERSION VERSION_LESS "3.10")
                string(REGEX REPLACE
                    "cmake_minimum_required\\(VERSION [^)]*\\)"
                    "cmake_minimum_required(VERSION 3.10)"
                    contents
                    "${contents}")

                file(WRITE "${LIBYAML_CMAKELISTS_FILE}" "${contents}")
                message(STATUS "Patched libyaml from ${CURRENT_VERSION} to 3.10")
            else()
                message(STATUS "libyaml CMake version ${CURRENT_VERSION} is sufficient")
            endif()
        else()
            message(WARNING "Could not find cmake_minimum_required in libyaml")
        endif()
    else()
        message(WARNING "libyaml CMakeLists.txt not found")
    endif()
endfunction()

patch_libyaml_cmake()
add_subdirectory(${PROJECT_SOURCE_DIR}/deps/libyaml
    EXCLUDE_FROM_ALL
)

set(BUILD_TESTING ${OLD_BUILD_TESTING} CACHE BOOL "" FORCE)