#ifndef AURA_YAML_H
#define AURA_YAML_H

#include "error_lib.h"
#include "radix_lib.h"
#include "yaml.h"
#include <stdbool.h>

#define a_init_yaml_node(yn, t, k, vt, te) \
    {                                      \
        yn.type = t;                       \
        yn.key = strdup(k);                \
        yn.val_type = vt;                  \
        yn.full_path = NULL;               \
        yn.tab_entry = te;                 \
    }

typedef enum {
    A_YAML_SCALAR,
    A_YAML_SEQUENCE,
    A_YAML_MAPPING
} aura_yml_type_t;

typedef enum {
    A_YAML_NONE,
    A_YAML_STRING,
    A_YAML_NUM,
    A_YAML_BOOL
} aura_yml_node_val_t;

struct aura_yml_vector {
    char *data;
    size_t size;
    size_t capacity;
    size_t elem_size;
};

/**
 * Tracks path
 * Associated index incase of a list
 * Nested structures within yaml...etc
 */
struct path_tracker {
    struct aura_yml_vector state_stack;
    struct aura_yml_vector index_stack;
    struct aura_yml_vector seq_context_stack;
    char *current_path;
    size_t path_capacity;
    char *full_path;
    size_t full_path_cap;
};

/* structure representing an error message */
struct aura_yml_err {
    char *message;
    char *path;
    size_t line;
    size_t column;
};

/**
 * Container to collect parsing errors
 * and define behaviour of parser when
 * error are encountered.
 */
struct aura_yml_err_ctx {
    struct aura_yml_err *errors;
    size_t err_cnt;
    size_t capacity;
    bool fail_fast;
};

/* General parser context */
struct aura_yml_conf_parser {
    struct path_tracker tracker;           /* keeps track of config levels during parsing*/
    struct aura_yml_validator *validators; /* list of validator functions to call */
    size_t validator_cnt;
    struct aura_yml_err_ctx *err_ctx; /* stores errors during parsing */
    void *usr_data_ctx;               /* opaque data passed and used as need be */
    bool in_panic;                    /* set when we encounter the first error */
    bool done;
};

/**
 * Holds list validation data
 * Not all fields are used
 * Fields are used only where applicable
 */
struct aura_validation_ctx {
    int min_cnt;
    int max_cnt;
    int current_cnt;
    bool is_valid;
    bool is_active;
};

typedef void (*aura_hook_cb)(struct aura_yml_conf_parser *p, yaml_event_t *e, struct aura_validation_ctx *vc);

/**
 *
 */
struct aura_yml_node {
    const char *key;       /* key as defined in yaml s*/
    const char *full_path; /* path for insertion into rax tree */
    union {
        void *ptr;
        const char *str_val;
        double double_val;
        uint64_t uint_val;
        int int_val;
        bool bool_val;
    };
    uint32_t tab_entry; /* table entry for 0(1) lookup */
    uint8_t type;       /* node type */
    uint8_t val_type;   /* value type for this node */
};

typedef void (*aura_hook_cb_2)(struct aura_yml_conf_parser *p, yaml_event_t *e, struct aura_yml_node *yn);

/**
 * Defines the validator associated with a path
 */
struct aura_yml_validator {
    const char *path;
    aura_hook_cb_2 cb;
};

/**
 * Tracks parsing state
 * Especially useful to handle nested structure
 */
typedef enum {
    A_STATE_KEY,
    A_STATE_VALUE,
    A_STATE_SEQUENCE,
    A_STATE_NESTED_MAPPING,
    A_STATE_NESTED_SEQUENCE
} aura_yml_parse_state_t;

/**
 * Tracks parsing state
 * Useful when handling sequence within yaml
 */
typedef enum {
    CONTEXT_NONE,
    CONTEXT_SEQUENCE_MAPPING
} aura_yml_conf_seq_ctx;

int aura_load_config(
  const char *file,
  struct aura_yml_validator validators[],
  size_t validator_cnt,
  struct aura_yml_err_ctx *err_ctx,
  void *usr_data);

int aura_load_config_fd(int fd, struct aura_yml_validator validators[], size_t validator_cnt, struct aura_yml_err_ctx *err_ctx, void *usr_data_ctx);

int aura_yaml_push_error(
  struct aura_yml_conf_parser *parser,
  const char *message,
  const char *path,
  size_t line,
  size_t column);

struct aura_yml_err_ctx *aura_create_yml_error_ctx(bool fail_fast);
void aura_free_yml_error_ctx(struct aura_yml_err_ctx *ctx);
void aura_dump_yml_node(struct aura_yml_node *yn);

#define YAML_ADD_ERROR(p, evt, fmt, ...)                                                                               \
    do {                                                                                                               \
        char buf[4096];                                                                                                \
        memset(buf, 0, sizeof(buf));                                                                                   \
        const char err_fmt[] = "\x1B[1;31mError\x1B[0m: ";                                                             \
        const char line_fmt[] = ":\x1B[1;31mline %lu\x1B[0m, \x1B[1;31mcol %lu\x1B[0m";                                \
        snprintf(buf, sizeof(err_fmt), "%s", err_fmt);                                                                 \
        snprintf(buf + strlen(buf), sizeof(buf) - sizeof(err_fmt) - sizeof(line_fmt), fmt, ##__VA_ARGS__);             \
        snprintf(buf + strlen(buf), sizeof(line_fmt), line_fmt, evt->start_mark.line + 1, evt->start_mark.column + 1); \
        aura_yaml_push_error(p, buf, p->tracker.current_path, evt->start_mark.line + 1, evt->start_mark.column + 1);   \
        if (p->err_ctx->fail_fast)                                                                                     \
            p->in_panic = true;                                                                                        \
    } while (0)

#endif