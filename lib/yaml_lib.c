#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "yaml_lib.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>

void inline a_dump_path_tracker(struct path_tracker *tr, bool is_daemon) {
    app_debug(is_daemon, 0, "current path -> %s\n", tr->current_path);
    app_debug(is_daemon, 0, "full path -> %s\n", tr->full_path);
    app_debug(is_daemon, 0, "path capacity -> %ld\n", tr->path_capacity);
    app_debug(is_daemon, 0, "current state stack -> %p\n", *(int *)tr->state_stack.data);
    app_debug(is_daemon, 0, "current index stack -> %p\n", *(int *)tr->index_stack.data);
}

void aura_dump_yml_node(struct aura_yml_node *yn) {
    app_debug(true, 0, "AURA YAML NODE:");
    switch (yn->type) {
    case A_YAML_SCALAR:
        app_debug(true, 0, "node scalar");
        break;
    case A_YAML_MAPPING:
        app_debug(true, 0, "node mapping");
        break;
    case A_YAML_SEQUENCE:
        app_debug(true, 0, "node sequence");
        break;
    default:
        app_debug(true, 0, "Unknown node value type");
    }

    app_debug(true, 0, "key: %s", yn->key);
    app_debug(true, 0, "full path: %s", yn->full_path);

    switch (yn->val_type) {
    case A_YAML_STRING:
        app_debug(true, 0, "str val: %s", yn->str_val);
        break;
    case A_YAML_NUM:
        app_debug(true, 0, "int value: %d", yn->uint_val);
        break;
    case A_YAML_BOOL:
        app_debug(true, 0, "bool value: %s", yn->bool_val ? "True" : "False");
        break;
    default:
        app_debug(true, 0, "Unknown node value type");
    }
}

static inline void a_vector_init(struct aura_yml_vector *vec_ptr, size_t capacity, size_t ele_size) {
    vec_ptr->data = malloc(capacity * ele_size);
    vec_ptr->size = 0;
    vec_ptr->capacity = capacity;
    vec_ptr->elem_size = ele_size;
}

/**
 * Gets a pointer to the element to add, and copies
 * item at that location
 */
static inline void a_vector_push(struct aura_yml_vector *vec_ptr, void *element) {
    if (vec_ptr->size >= vec_ptr->capacity) {
        vec_ptr->capacity *= 2;
        vec_ptr->data = realloc(vec_ptr->data, vec_ptr->capacity);
    }
    memcpy(vec_ptr->data + vec_ptr->size * vec_ptr->elem_size, element, vec_ptr->elem_size);
    vec_ptr->size++;
}

static inline void *a_vector_pop(struct aura_yml_vector *vec_ptr) {
    if (vec_ptr->size == 0)
        return NULL;
    vec_ptr->size--;
    return (char *)vec_ptr->data + vec_ptr->size * vec_ptr->elem_size;
}

/* Returns a pointer to the last element */
static inline void *a_vector_peek(struct aura_yml_vector *vec_ptr) {
    if (vec_ptr->size == 0)
        return NULL;
    return (char *)vec_ptr->data + ((vec_ptr->size - 1) * vec_ptr->elem_size);
}

static inline void a_vector_free(struct aura_yml_vector *vec_ptr) {
    free(vec_ptr->data);
    vec_ptr->data = NULL;
    vec_ptr->size = vec_ptr->capacity = vec_ptr->elem_size = 0;
}

static inline void free_path_tracker(struct path_tracker *tr) {
    free(tr->current_path);
    free(tr->full_path);
    a_vector_free(&tr->state_stack);
    a_vector_free(&tr->index_stack);
    a_vector_free(&tr->seq_context_stack);
}

struct aura_yml_err_ctx *aura_create_yml_error_ctx(bool fail_fast) {
    struct aura_yml_err_ctx *ctx;

    ctx = malloc(sizeof(*ctx));
    if (ctx == NULL)
        sys_exit(true, errno, "Failed to allocate needed memory");

    ctx->errors = NULL;
    ctx->capacity = 0;
    ctx->err_cnt = 0;
    ctx->fail_fast = fail_fast;

    return ctx;
}

void aura_free_yml_error_ctx(struct aura_yml_err_ctx *ctx) {
    int i;
    if (!ctx)
        return;

    for (i = 0; i < ctx->err_cnt; ++i) {
        free(ctx->errors[i].message);
        free(ctx->errors[i].path);
    }

    if (ctx->errors) {
        free(ctx->errors);
        ctx->errors = NULL;
    }
    ctx->err_cnt = ctx->capacity = 0;
    free(ctx);
}

/**
 *
 */
int aura_yaml_push_error(struct aura_yml_conf_parser *p, const char *msg, const char *path, size_t line, size_t col) {
    struct aura_yml_err_ctx *ctx = p->err_ctx;
    struct aura_yml_err *err;

    if (ctx->err_cnt >= ctx->capacity) {
        ctx->capacity = ctx->capacity ? ctx->capacity * 2 : 10;
        ctx->errors = realloc(ctx->errors, ctx->capacity * sizeof(*err));
    }

    err = &ctx->errors[ctx->err_cnt++];
    err->message = strdup(msg);
    err->path = path ? strdup(path) : NULL;
    err->line = line;
    err->column = col;
}

/**
 * We update the current path we have, adding appending the '.new_seg'
 * i.e, old_seg.curr_seg.new_seg
 * This is used mostly to update paths for comparison
 * with validator paths
 */
static void a_update_current_path(struct path_tracker *tr, const char *new_segment, aura_yml_parse_state_t state) {
    size_t new_length = strlen(tr->current_path) + strlen(new_segment) + 2;

    if (new_length >= tr->path_capacity) {
        while (new_length >= tr->path_capacity)
            tr->path_capacity = new_length * 2;

        tr->current_path = realloc(tr->current_path, tr->path_capacity);
    }

    if (state != A_STATE_SEQUENCE)
        if (tr->current_path[0] != '\0')
            strcat(tr->current_path, ".");

    strcat(tr->current_path, new_segment);
}

/**
 * Update the full path separately, the full path contains the
 * details like current index incase of nested structures
 */
static void a_update_full_path(struct path_tracker *tr, const char *new_segment) {
    size_t new_length = strlen(tr->full_path) + strlen(new_segment) + 2;

    if (new_length >= tr->full_path_cap) {
        while (new_length >= tr->full_path_cap)
            tr->full_path_cap = new_length * 2;

        tr->full_path = realloc(tr->full_path, tr->full_path_cap);
    }

    if (tr->full_path[0] != '\0')
        strcat(tr->full_path, ".");

    strcat(tr->full_path, new_segment);
}

/**
 *
 */
static bool inline a_path_has_prefix(const char *path, const char *prefix) {
    if (!path)
        return false;
    return (strncmp(path, prefix, strlen(prefix)) == 0);
}
/**
 *
 */
static const char *get_map_key(const char *path) {
    char *key = strrchr(path, '.');
    if (!key)
        return path;

    size_t len = strlen(key);

    if (!key || len == 1)
        return NULL;

    return key + 1;
}

/**
 *
 */
static void a_handle_mapping_start(struct aura_yml_conf_parser *p, yaml_event_t *evt) {
    aura_yml_parse_state_t *seq_ctx, new_ctx;
    int *curr_idx;
    struct path_tracker *tr = &p->tracker;
    aura_yml_parse_state_t state, *curr_state = a_vector_peek(&tr->state_stack);
    // char path[4096] = {0};

    if (curr_state && *curr_state == A_STATE_VALUE) {
        *curr_state = A_STATE_NESTED_MAPPING;
    } else if (curr_state && *curr_state == A_STATE_SEQUENCE) {
        int *curr_idx = a_vector_peek(&tr->index_stack);
        seq_ctx = a_vector_peek(&tr->seq_context_stack);

        if (seq_ctx)
            *seq_ctx = CONTEXT_SEQUENCE_MAPPING;

        if (curr_idx) {
            /* we build path upfront because it's easier this way */
            char index_str[32];
            char idx_str[32];

            snprintf(index_str, sizeof(index_str), "[*]");
            snprintf(idx_str, sizeof(idx_str), "%d", *curr_idx);

            a_update_current_path(tr, index_str, A_STATE_SEQUENCE);
            a_update_full_path(tr, idx_str);
            (*curr_idx)++;
        }
    }

    /**
     * We run validators after updating the path inorder
     * not to insert nested structures correctly
     */
    struct aura_yml_node yn = {
      .type = A_YAML_MAPPING,
      .key = get_map_key(tr->current_path),
      .full_path = tr->full_path,
      .str_val = NULL,
    };

    for (int i = 0; i < p->validator_cnt; ++i) {
        if (a_path_has_prefix(tr->current_path, p->validators[i].path)) {
            if (p->validators[i].cb != NULL) {
                p->validators[i].cb(p, evt, &yn);
                if (p->in_panic)
                    return;
                break;
            }
        }
    }

    state = A_STATE_KEY;
    a_vector_push(&tr->state_stack, &state);

    /* set context for a new mapping */
    new_ctx = CONTEXT_NONE;
    a_vector_push(&tr->seq_context_stack, &new_ctx);
}

/**
 *
 */
static void a_handle_sequence_start(struct aura_yml_conf_parser *p, yaml_event_t *evt) {
    int i;
    aura_yml_conf_seq_ctx seq_cxt;
    struct path_tracker *tr = &p->tracker;
    aura_yml_parse_state_t state, *curr_state = a_vector_peek(&tr->state_stack);
    struct aura_yml_node yn = {
      .type = A_YAML_SEQUENCE,
      .key = get_map_key(tr->current_path),
      .full_path = tr->full_path,
      .str_val = NULL,
    };

    // app_debug(true, 0, "SEQUENCE START: Path: %s", tr->current_path);

    /**
     * If the previous state was a mapping, another mapping
     * puts us inside a nested structure, We won't expect
     * the mapping value we had prepared for anymore.
     * So we update the curr state
     */
    if (curr_state && *curr_state == A_STATE_VALUE) {
        *curr_state = A_STATE_NESTED_SEQUENCE;
    }

    /**
     * Run validator to catch lists that don't pass the
     * criteria
     */
    for (int i = 0; i < p->validator_cnt; ++i) {
        if (a_path_has_prefix(tr->current_path, p->validators[i].path)) {
            if (p->validators[i].cb != NULL) {
                p->validators[i].cb(p, evt, &yn);
                if (p->in_panic)
                    return;
                break;
            }
        }
    }

    state = A_STATE_SEQUENCE;
    a_vector_push(&tr->state_stack, &state);
    int initial_index = 0;
    a_vector_push(&tr->index_stack, &initial_index);

    seq_cxt = CONTEXT_NONE;
    a_vector_push(&tr->seq_context_stack, &seq_cxt);
}

/**
 *
 */
static void a_handle_structure_end(struct aura_yml_conf_parser *p, yaml_event_t *evt) {
    struct path_tracker *tr = &p->tracker;
    aura_yml_parse_state_t *curr_state, *parent_state;
    aura_yml_conf_seq_ctx *parent_cxt;
    struct aura_yml_validator *validator_ctx;
    int *curr_idx;

    if (tr->state_stack.size > 1) {
        curr_state = a_vector_peek(&tr->state_stack);

        if (curr_state && *curr_state == A_STATE_SEQUENCE && tr->index_stack.size > 0) {
            curr_idx = a_vector_pop(&tr->index_stack);
        }
        a_vector_pop(&tr->seq_context_stack);
        a_vector_pop(&tr->state_stack);

        parent_state = a_vector_peek(&tr->state_stack);
        parent_cxt = a_vector_peek(&tr->seq_context_stack);

        if (*parent_cxt == CONTEXT_SEQUENCE_MAPPING) {
            /**
             * If we were in a list mapping, we remove the [] at the end of the path
             * So something like server[0] simply becomes server
             */
            char *last_bracket = strrchr(tr->current_path, '[');
            if (last_bracket)
                *last_bracket = '\0';

            char *last_dot = strrchr(tr->full_path, '.');
            if (last_dot)
                *last_dot = '\0';

        } else {
            if (parent_state && (*parent_state == A_STATE_NESTED_MAPPING || *parent_state == A_STATE_NESTED_SEQUENCE)) {
                /**
                 * when exiting a nested structure, revert to mapping key state,
                 * and clean the key that started the nested structure
                 */
                *parent_state = A_STATE_KEY;
            }

            /* we locate last . and truncate path */
            char *last_dot_curr = strrchr(tr->current_path, '.');
            if (last_dot_curr)
                *last_dot_curr = '\0';
            else
                /* empty path */
                tr->current_path[0] = '\0';

            char *last_dot_full = strrchr(tr->full_path, '.');
            if (last_dot_full)
                *last_dot_full = '\0';
            else
                tr->full_path[0] = '\0';
        }
    }
}

/**
 *
 */
static void a_handle_scalar(struct aura_yml_conf_parser *p, yaml_event_t *evt) {
    struct path_tracker *tr = &p->tracker;
    aura_yml_parse_state_t *curr_state = (aura_yml_parse_state_t *)a_vector_peek(&tr->state_stack);
    const char *value = (const char *)evt->data.scalar.value;
    int i;
    aura_yml_parse_state_t *seq_ctx, *parent_ctx;

    // app_debug(true, 0, "SCALAR VALUE: path: %s, value: %s", tr->full_path, value);

    seq_ctx = a_vector_pop(&tr->seq_context_stack);
    parent_ctx = a_vector_peek(&tr->seq_context_stack);
    a_vector_push(&tr->seq_context_stack, &seq_ctx);

    if (curr_state && *curr_state == A_STATE_KEY) {
        /* we have a key, let's prepare for a value */
        a_update_current_path(tr, value, A_STATE_KEY);
        a_update_full_path(tr, value);
        *curr_state = A_STATE_VALUE;
    } else if (curr_state && *curr_state == A_STATE_VALUE) {
        struct aura_yml_node yn = {
          .type = A_YAML_SCALAR,
          .key = get_map_key(tr->current_path),
          .full_path = tr->full_path,
          .str_val = value,
        };

        /* run validator */
        for (int i = 0; i < p->validator_cnt; ++i) {
            if (a_path_has_prefix(tr->current_path, p->validators[i].path)) {
                if (p->validators[i].cb != NULL) {
                    p->validators[i].cb(p, evt, &yn);
                    if (p->in_panic)
                        return;
                    break;
                }
            }
        }

        /* truncate path at last dot */
        char *last_dot_curr = strrchr(tr->current_path, '.');
        if (last_dot_curr)
            *last_dot_curr = '\0';
        else {
            /* we are at root level, truncate path back to empty string */
            tr->current_path[0] = '\0';
        }

        char *last_dot_full = strrchr(tr->full_path, '.');
        if (last_dot_full)
            *last_dot_full = '\0';
        else {
            tr->full_path[0] = '\0';
        }

        *curr_state = A_STATE_KEY;
    } else if (curr_state && *curr_state == A_STATE_SEQUENCE) {
        char path[4096];
        int *curr_idx = a_vector_peek(&tr->index_stack);

        if (curr_idx) {
            /**
             * Construct path to insert it as part of sequence.
             * We resuse the same key but with value attached.
             */
            snprintf(path, sizeof(path), "%s.%d", tr->full_path, *curr_idx);
            struct aura_yml_node yn = {
              .type = A_YAML_SCALAR,
              .key = get_map_key(tr->current_path),
              .full_path = path,
              .str_val = value,
            };

            /* run validator */
            for (int i = 0; i < p->validator_cnt; ++i) {
                if (a_path_has_prefix(tr->current_path, p->validators[i].path)) {
                    if (p->validators[i].cb != NULL) {
                        p->validators[i].cb(p, evt, &yn);
                        if (p->in_panic)
                            return;
                        break;
                    }
                }
            }
            (*curr_idx)++;
        }
    }
}

/**
 *
 */
static int a_yaml_parse_config(struct aura_yml_conf_parser *p, yaml_parser_t *yp) {
    yaml_event_t evt;

    do {
        if (!yaml_parser_parse(yp, &evt)) {
            yaml_event_delete(&evt);
            break;
        }

        switch (evt.type) {
        case YAML_STREAM_END_EVENT:
            p->done = true;
            int last_idx = p->validator_cnt - 1;
            /* parent validator is the last validator in the table */
            // if (validator_is_empty(&p->validators[p->validator_cnt - 1].validator) || last_idx < 0)
            // break;
            // p->validators[last_idx].validator.cb(p, &evt, p->validators[last_idx].validator.v_ctx);
            break;
        case YAML_MAPPING_START_EVENT:
            a_handle_mapping_start(p, &evt);
            break;
        case YAML_SEQUENCE_START_EVENT:
            a_handle_sequence_start(p, &evt);
            break;
        case YAML_MAPPING_END_EVENT:
        case YAML_SEQUENCE_END_EVENT:
            a_handle_structure_end(p, &evt);
            break;
        case YAML_SCALAR_EVENT:
            a_handle_scalar(p, &evt);
            break;
        default:
            break;
        }

        yaml_event_delete(&evt);
    } while (!p->in_panic && !p->done);

    return 0;
}

/**/
static inline void a_init_path_tracker(struct path_tracker *tr) {
    tr->current_path = malloc(1024);
    tr->current_path[0] = '\0';
    tr->path_capacity = 1024;

    tr->full_path = malloc(1024);
    tr->full_path[0] = '\0';
    tr->full_path_cap = 1024;

    a_vector_init(&tr->state_stack, 10, sizeof(aura_yml_parse_state_t));
    a_vector_init(&tr->index_stack, 10, sizeof(int));
    a_vector_init(&tr->seq_context_stack, 10, sizeof(aura_yml_parse_state_t));
}

/**
 *
 */
static inline void a_yaml_config_parser_free(struct aura_yml_conf_parser *p) {
    free_path_tracker(&p->tracker);
}

/**
 *
 */
static int a_load_config_(FILE *fp, struct aura_yml_validator validators[], size_t validator_cnt, struct aura_yml_err_ctx *err_ctx, void *usr_data_ctx) {
    yaml_parser_t yaml_parser;
    struct aura_yml_conf_parser p;
    int ret_val;

    if (!yaml_parser_initialize(&yaml_parser))
        return 1;

    p.in_panic = false;
    p.done = false;
    p.validators = validators;
    p.validator_cnt = validator_cnt;
    p.err_ctx = err_ctx;
    p.usr_data_ctx = usr_data_ctx;
    a_init_path_tracker(&p.tracker);
    yaml_parser_set_input_file(&yaml_parser, fp);

    a_yaml_parse_config(&p, &yaml_parser);

    if (p.in_panic) {
        ret_val = 0;
        goto out;
    }
    ret_val = 0;

out:
    fclose(fp);
    yaml_parser_delete(&yaml_parser);
    a_yaml_config_parser_free(&p);
    return ret_val;
}

/**
 *
 */
int aura_load_config(const char *filename, struct aura_yml_validator validators[], size_t validator_cnt, struct aura_yml_err_ctx *err_ctx, void *usr_data_ctx) {
    FILE *fp;

    fp = fopen(filename, "rb");
    if (ferror(fp)) {
        sys_alert(true, errno, "failed to open config file %s", filename);
        return 1;
    }

    return a_load_config_(fp, validators, validator_cnt, err_ctx, usr_data_ctx);
}

/**
 *
 */
int aura_load_config_fd(int fd, struct aura_yml_validator validators[], size_t validator_cnt, struct aura_yml_err_ctx *err_ctx, void *usr_data_ctx) {
    FILE *fp;

    fp = fdopen(fd, "rb");
    if (ferror(fp)) {
        sys_alert(true, errno, "failed to get fle descriptor");
        return 1;
    }

    return a_load_config_(fp, validators, validator_cnt, err_ctx, usr_data_ctx);
}
