#ifndef AURA_TEST_H
#define AURA_TEST_H

#include "compiler_lib.h"

#include <stdbool.h>

/** This is going rough!! */

/* Max size of parameter description string */
#define A_MAX_PARAM_DESC_SIZE 128

/* Max size of status comment */
#define A_MAX_STATUS_COMMENT_SIZE 256

/**
 *
 */
typedef enum {
    A_UNIT_SUCCESS, /* Test not failed and not skipped */
    A_UNIT_FAILURE, /* Test has failed */
    A_UNIT_SKIPPED, /* Test has been skipped */
} aura_unit_test_status_t;

typedef enum {
    A_UNIT_ASSERTION,
    A_UNIT_EXPECTATION,
} aura_unit_assert_type_t;

typedef void (*aura_try_catch_fn_t)(void *);

/**/
struct aura_unit_loc {
    const char *file;
    int line;
};

#define A_UNIT_CURRENT_LOC {.file = __FILE__, .line = __LINE__}

struct aura_unit_assert {};

/**
 * try catch
 */
struct aura_unit_try_catch {
    struct aura_unit_t *test;
    int try_res;
    aura_try_catch_fn_t try_;
    aura_try_catch_fn_t catch_;
    void *ctx;
};

void aura_unit_try_catch_run(struct aura_unit_try_catch *tc, void *ctx);

/**
 * Running instance of a test
 */
struct aura_unit_t {
    void *t_data; /* used to store arbitrary data (look into it) */

    /* internal */
    const char *name;          /* Name of the unit test */
    struct string_stream *log; /* points to case log, used fot logging messages */
    struct aura_unit_try_catch try_catch;
    const void *param_value;        /* current parameter value for the test case */
    int param_index;                /* index of the paramater in a parameterized test */
    aura_unit_test_status_t status; /* Read after test case finished */
    char status_comment[A_MAX_STATUS_COMMENT_SIZE];
    struct aura_unit_loc loc;
};

/**
 * Single test case
 */
struct aura_unit_t_case {
    void (*run_fn)(struct aura_unit_t *test);
    const char *name;

    aura_unit_test_status_t status;
    // char *module_name;
    // struct string_stream *log;
};

/**
 * Collection of related tests
 */
struct aura_unit_t_suite {
    const char *name[256];
    int (*suite_init)(struct aura_unit_t_suite *suite);
    void (*suite_exit)(struct aura_unit_t_suite *suite);
    int (*init)(struct aura_unit_t *test);
    void (*exit)(struct aura_unit_t *test);
    struct aura_unit_t_case *test_case;

    char status_comment[A_MAX_STATUS_COMMENT_SIZE];
    struct sting_stream *log;
    int suite_init_err;
    bool initialized;
};

/**
 * An array of suites
 */
struct aura_unit_t_suite_set {
    struct aura_unit_t_suite *const *start;
    struct aura_unit_t_suite *const *end;
};

/**
 * UNIT_CASE - A helper for creating a &struct unit_case
 * @test_name: a reference to the test case function
 */
#define a_unit_test_case(test) \
    {                          \
      .run_fn = test,          \
      .name = #test,           \
    }

int aura_test_suites_init(struct aura_unit_t_suite **suites, int num_of_suites);
void aura_test_suites_exit(struct aura_unit_t_suite **suites, int num_of_suites);

void aura_unit_exec_run_tests(struct aura_unit_t_suite *suite_set);
void aura_unit_exec_list_test(struct aura_unit_t_suite *suite);

int aura_unit_run_all_tests(void);

void a_unit_free_suite_set(struct aura_unit_t_suite suite_set);

#define _a_unit_test_suites(unique_array, ...)                                        \
    static struct aura_ *unique_array[] __aligned(sizeof(struct aura_unit_t_suite *)) \
      __used __section(".a_unit_test_suites") = {__VA_ARGS__}

/**
 * unit_test_suites(): used to register one or more &struct unit_suite with kunit
 * @_suites: a statically allocated list of &struct unit_suite
 *
 * Register @suite with the test framework.
 * This is done by placing the array of struct unit_suite * in the unit_test_suites ELF section.
 * When builtin, unit tests are all run via the executor at boot, and when
 * built as a module, they run on module load.
 */
#define a_unit_test_suites(_suites...) _a_unit_test_suites(_UNIQUE_ID(array), ##_suites)
#define a_unit_test_suite(suite) _a_unit_test_suites(&suite)

#define _a_unit_init_test_suites(unique_array, ...)                                               \
    static struct aura_unit_t_suite *unique_array[] __aligned(sizeof(struct aura_unit_t_suite *)) \
      __used __section("a_unit_init_test_suites") = {__VA_ARGS__}

/**
 * a_unit_test_init_section_suites(): used to register one or more &struct unit_suite
 *  containing init functions or unit data
 * @_suite: a statically allocated list of &struct unit_suite
 *
 * This is similar to unit_test_suites() except that it compiles the list of
 * suites during init phase.
 * This macro also suffixes the array and suite declarations, it marks with _probe;
 * so that modpost suppresses warnings about referencing init data for symbols named
 * in this manner.
 * Not this tests are not able to run after boot
 */
#define _a_unit_test_init_section_suites(_suites...) \
    _unit_init_test_suites(CONCATENATE(_UNIQUE_ID(array), _probe), ##_suites)

#define a_unit_test_init_section_suite(suite) _a_unit_test_init_section_suites(&suite)

#define a_unit_suite_for_each_test_case(suite, test_case) \
    for (test_case = suite->test_cases; test_case->run_fn; test_case++)

aura_unit_test_status_t aura_unit_suite_has_succeeded(struct aura_unit_t_suite *suite);

/**
 * Mark test as skipped
 */
#define a_unit_mark_skipped(test_or_suite, fmt, ...)                                                 \
    do {                                                                                             \
        ((test_or_suite)->status, A_UNIT_SKIPPED);                                                   \
        /*scnprintf((test_or_suite)->status_comment, MAX_STATUS_COMMENT_SIZE, fmt, ##__VA_ARGS__);*/ \
    } while (0)

/**
 * Skip test, possibly halt test after skip
 */
#define a_unit_skip(test_or_suite, fmt, ...)                          \
    do {                                                              \
        a_unit_mark_skipped((test_or_suite), fmt, ##__VA_ARGS__);     \
        /*aura_unit_try_catch_throw(&((test_or_suite)->try_catch));*/ \
    } while (0)

/**
 * Must be called at the beginning of each UNIT_*_ASSERTION().
 * Cf. UNIT_CURRENT_LOC.
 */
#define A_UNIT_SAVE_LOC(test)       \
    do {                            \
        (test->loc.file, __FILE__); \
        (test->loc.line, __LINE__); \
    } while (0)

/**
 * A no-op expectation. Only exists for code clarity.
 * @test; The test context object.
 */
#define A_UNIT_SUCCEED(test) A_UNIT_SAVE_LOC(test)

#define _A_UNIT_FAILED(test, assert_type, assert_class, assert_format, INITIALIZER, fmt, ...) \
    do {                                                                                      \
        static const struct aura_unit_loc loc = A_UNIT_CURRENT_LOC;                           \
        const struct assert_class __assertion = INITIALIZER;                                  \
        /* a_unit_do_failed_assertion() */                                                    \
        /* if (assert_type == A_UNIT_ASSERTION) _a_unit_abort(test); */                       \
    } while (0)

#define A_UNIT_FAIL_ASSERTION(test, assert_type, fmt, ...)                                                           \
    do {                                                                                                             \
        /* _A_UNIT_SAVE_LOC(test); */                                                                                \
        /* _A_UNIT_FAILED(test, assert_type, a_unit_fail_assert, a_unit_fail_assert_fmt, {}, fmt, ##__VA_ARGS__); */ \
    } while (0)

/**
 * UNIT_FAIL(): Always causes a test to fail when evaluated.
 * @test: The test context object.
 * @fmt: an informational message to be printed when the assertion is made.
 * @...: string format arguments.
 *
 * The opposite of UNIT_SUCCEED(), it is an expectation that always fails. In
 * other words, it always results in a failed expectation, and consequently always
 * causes the test case to fail when evaluated.
 */
// #define A_UNIT_FAILED(test, fmt, ...) A_UNIT_FAIL_ASSERTION(test, A_UNIT_EXPECTATION, fmt, ##__VA_ARGS__)

/* Helper to safely pass around an initializer list to other macros */
#define A_UNIT_INIT_ASSERT(initializers...) {initializers}

#define A_UNIT_UNARY_ASSERTION(test, assert_type, condition_, expected_true_, fmt, ...)  \
    do {                                                                                 \
        A_UNIT_SAVE_LOC(test);                                                           \
        if (likely(!!(condition_) == !!expected_true_))                                  \
            break;                                                                       \
                                                                                         \
        _A_UNIT_FAILED(                                                                  \
          test,                                                                          \
          assert_type,                                                                   \
          a_unit_unary_assert,                                                           \
          a_unit_unary_assert_format,                                                    \
          A_UNIT_INIT_ASSERT(.condition = #condition_, .expected_true = expected_true_), \
          fmt,                                                                           \
          ##__VA_ARGS__);                                                                \
    } while (0)

#endif