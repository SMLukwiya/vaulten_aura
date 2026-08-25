#include "blobber/lib.h"
#include "error_lib.h"
#include "fn/lib.h"
#include "radix/tree.h"
#include "unix/sock.h"
#include "utils_lib.h"
#include "yaml/lib.h"

#include <regex.h>
#include <stdio.h>
#include <strings.h>

static bool fn_id_set = false;

/**
 * Expects field name, value expected and value parsed in that order
 */
const char fn_config_valid[] = "\x1B[1;32mConfig valid\x1B[0m";
const char fn_invalid_single_field_format[] = "Invalid %s, Expected value to be %s but got %s";

/**
 * Get a slot for a yaml node in the yaml node pool
 */
static inline uint32_t a_get_node_off(struct aura_yml_conf_parser *p, yaml_event_t *evt) {
    struct aura_yml_fn_data_ctx *us;

    us = (struct aura_yml_fn_data_ctx *)p->usr_data_ctx;

    if (us->node_vec.cnt >= us->node_vec.cap) {
        us->node_vec.cap = us->node_vec.cap < 5 ? 5 : us->node_vec.cap * 2;
        us->node_vec.entries = realloc(us->node_vec.entries, us->node_vec.cap * sizeof(struct aura_yml_node));
        if (!us->node_vec.entries) {
            YAML_ADD_ERROR(p, evt, "Out of memory");
            return UINT32_MAX;
        }
    }
    memset(&(us->node_vec.entries[us->node_vec.cnt]), 0, sizeof(struct aura_yml_node));
    return us->node_vec.cnt++;
}

/**
 * Insert the parsed yaml node into a tree with the node offset as
 * the data associated with a given tree entry
 */
static inline void a_parse_tree_insert(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_yml_node *yn, uint32_t off) {
    struct aura_yml_fn_data_ctx *us;
    aura_rax_tree_t *t;
    int res;

    us = (struct aura_yml_fn_data_ctx *)p->usr_data_ctx;
    t = &us->parse_tree;

    res = aura_rax_insert(t, yn->full_path, strlen(yn->full_path), A_RAX_NODE_TYPE_SPARSE, a_rax_data_init_int(off));
    if (!res) {
        YAML_ADD_ERROR(p, evt, "Failed to parse yaml");
        app_alert(true, 0, "Failed to insert yaml node into rax tree!");
    }
}

/**
 *
 */
static inline void a_ensure_node_is_scalar(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_yml_node *yn) {
    if (yn->type != A_YAML_SCALAR)
        YAML_ADD_ERROR(p, evt, "Invalid %s, Expected a valid scalar value", yn->full_path);
}

static inline void a_ensure_node_is_mapping(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_yml_node *yn) {
    if (yn->type != A_YAML_MAPPING)
        YAML_ADD_ERROR(p, evt, "Invalid %s, Expected a valid mapping", yn->full_path);
}

static inline void a_ensure_node_is_sequence(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_yml_node *yn) {
    if (yn->type != A_YAML_SEQUENCE)
        YAML_ADD_ERROR(p, evt, "Invalid %s, Expected a valid sequence", yn->full_path);
}

/**
 * AURA YAML VERSION
 */
void a_fn_validate_yaml_version(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_yml_node *yn) {
    struct aura_yml_fn_data_ctx *usr_data;
    const char *value = evt->data.scalar.value;

    usr_data = (struct aura_yml_fn_data_ctx *)p->usr_data_ctx;

    a_ensure_node_is_scalar(p, evt, yn);
    if (!value || strlen(value) == 0) {
        YAML_ADD_ERROR(p, evt, fn_invalid_single_field_format, "yaml version", "v1beta1", "empty string");
        return;
    }

    if (strcmp(value, "v1beta1") != 0)
        YAML_ADD_ERROR(p, evt, fn_invalid_single_field_format, "yaml version", "v1beta1", value);

    usr_data->seen_aura_version = true;
}

/**
 * FUNCTION
 */
void a_fn_validate_function(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_yml_node *yn) {
    struct aura_yml_fn_data_ctx *usr_data;
    aura_rax_tree_t *rax;
    uint32_t node_off;
    struct aura_yml_node *yml_node;
    int res;

    usr_data = (struct aura_yml_fn_data_ctx *)p->usr_data_ctx;
    rax = &usr_data->parse_tree;

    if (!yn) {
        app_alert(true, 0, "Validation node not passed: fix asap");
        return;
    }

    if (usr_data->extract && !rax) {
        app_alert(true, 0, "Trying to extract data without parser tree!: fix asap");
        return;
    }

    /* FN starting map */
    if (strcmp(yn->key, "function") == 0) {
        a_ensure_node_is_mapping(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_NONE, A_IDX_FN_FUNCTION);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* FN name */
    if (strcmp(yn->key, "name") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);

        if (strlen(yn->str_val) > A_FN_NAME_MAX_LEN) {
            YAML_ADD_ERROR(p, evt, "Function name length exceeds max allowed");
            return;
        }

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_STRING, A_IDX_FN_NAME);
            yml_node->str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* FN description */
    if (strcmp(yn->key, "description") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_STRING, A_IDX_FN_DESCRIPTION);
            yml_node->str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* FN version */
    if (strcmp(yn->key, "version") == 0) {
        int version;
        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_STRING, A_IDX_FN_VERSION);
            yml_node->str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* FN entry point */
    if (strcmp(yn->key, "entrypoint") == 0) {
        int entry_fd;
        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            /**
             * We are sure we have the function directory fd here,
             * because we pass it when deploying a fn. We can there therefore
             * perform validation on the entry file upfront
             */
            entry_fd = openat(usr_data->dir_fd, yn->str_val, O_RDONLY);
            if (entry_fd < 0) {
                YAML_ADD_ERROR(p, evt, "Failed to open entry file");
                return;
            }
            close(entry_fd);
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_STRING, A_IDX_FN_ENTRY_POINT);
            yml_node->str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* FN host @todo: could be better */
    if (strcmp(yn->key, "host") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_STRING, A_IDX_FN_HOST);
            yml_node->str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
    }

    /* Insert FN ID manually as last field */
    if (usr_data->extract && !p->in_panic && !fn_id_set) {
        uint64_t fn_id = aura_now_ms(CLOCK_REALTIME);

        node_off = a_get_node_off(p, evt);
        yml_node = &usr_data->node_vec.entries[node_off];
        a_init_yaml_node(yml_node, A_YAML_SCALAR, "id", A_YAML_UINT, A_IDX_FN_ID);
        yml_node->uint_val = fn_id;

        /* Modify path for tree insertion */
        yn->full_path = "function.id";
        a_parse_tree_insert(p, evt, yn, node_off);
        fn_id_set = true;
    }
    return;
}

/* ENV */
void a_fn_validate_env(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_yml_node *yn) {
    struct aura_yml_fn_data_ctx *usr_data;
    aura_rax_tree_t *rax;
    uint32_t node_off;
    struct aura_yml_node *yml_node;
    int res;

    usr_data = (struct aura_yml_fn_data_ctx *)p->usr_data_ctx;
    rax = &usr_data->parse_tree;

    if (!yn) {
        app_alert(true, 0, "Validation node not passed: fix asap");
        return;
    }

    if (usr_data->extract && !rax) {
        app_alert(true, 0, "Trying to extract data without parser tree!: fix asap");
        return;
    }

    /* FN env vars */
    if (strcmp(yn->key, "env") == 0) {
        a_ensure_node_is_sequence(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_NONE, A_IDX_FN_ENV);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    if (strcmp(yn->key, "env[*]") == 0) {
        a_ensure_node_is_mapping(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_NONE, A_IDX_FN_NONE);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* env[*].name */
    if (strcmp(yn->key, "name") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_STRING, A_IDX_FN_NONE);
            yml_node->str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* env[*].value */
    if (strcmp(yn->key, "value") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_STRING, A_IDX_FN_NONE);
            yml_node->str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }
}

bool aura_fn_validate_http_method(const char *method, aura_fn_http_method_t *value) {
    *value = 0;

    if (strcasecmp(method, "GET") == 0) {
        *value = GET;
        return true;
    }

    if (strcasecmp(method, "POST") == 0) {
        *value = POST;
        return true;
    }

    if (strcasecmp(method, "PUT") == 0) {
        *value = PUT;
        return true;
    }

    if (strcasecmp(method, "DELETE") == 0) {
        *value = DELETE;
        return true;
    }

    if (strcasecmp(method, "HEAD") == 0) {
        *value = HEAD;
        return true;
    }

    return false;
}

bool aura_fn_validate_misfire_policy(const char *policy, aura_fn_cron_misfire_policy_t *value) {
    *value = 0;

    if (strcmp(policy, "ignore") == 0) {
        *value = IGNORE;
        return true;
    }

    if (strcmp(policy, "fire_now") == 0) {
        *value = FIRE_NOW;
        return true;
    }

    if (strcmp(policy, "reschedule") == 0) {
        *value = RESCHEDULE;
        return true;
    }

    return false;
}

/* Triggers */
void a_fn_validate_triggers(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_yml_node *yn) {
    struct aura_yml_fn_data_ctx *usr_data;
    aura_rax_tree_t *rax;
    uint32_t node_off;
    struct aura_yml_node *yml_node;
    int res;

    usr_data = (struct aura_yml_fn_data_ctx *)p->usr_data_ctx;
    rax = &usr_data->parse_tree;

    if (!yn) {
        app_alert(true, 0, "Validation node not passed: fix asap");
        return;
    }

    if (usr_data->extract && !rax) {
        app_alert(true, 0, "Trying to extract data without parser tree!: fix asap");
        return;
    }

    /* FN triggers mapping */
    if (strcmp(yn->key, "triggers") == 0) {
        a_ensure_node_is_mapping(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_NONE, A_IDX_FN_TRIGGERS);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* HTTP trigger */
    if (strcmp(yn->key, "http") == 0) {
        a_ensure_node_is_mapping(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_NONE, A_IDX_FN_HTTP_TRIGGER);
            a_parse_tree_insert(p, evt, yn, node_off);
            usr_data->trigger_type = A_FN_TRIGGER_HTTP;
        }
        return;
    }

    /* http path */
    if (strcmp(yn->key, "path") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->trigger_type != A_FN_TRIGGER_HTTP) {
            YAML_ADD_ERROR(p, evt, "Invalid %p, path must be under HTTP trigger type.", yn->full_path);
            return;
        }

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_STRING, A_IDX_FN_NONE);
            yml_node->str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* http method */
    if (strcmp(yn->key, "method") == 0) {
        aura_fn_http_method_t method;
        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->trigger_type != A_FN_TRIGGER_HTTP) {
            YAML_ADD_ERROR(p, evt, "Invalid %p, method must be under HTTP trigger type.", yn->full_path);
            return;
        }

        if (!aura_fn_validate_http_method(yn->str_val, &method)) {
            YAML_ADD_ERROR(p, evt, "Invalid HTTP method %s", yn->str_val);
            return;
        }

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_INT, A_IDX_FN_NONE);
            yml_node->int_val = method;
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* CRON Trigger */
    if (strcmp(yn->key, "cron") == 0) {
        a_ensure_node_is_mapping(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_NONE, A_IDX_FN_CRON_TRIGGER);
            a_parse_tree_insert(p, evt, yn, node_off);
            usr_data->trigger_type = A_FN_TRIGGER_CRON;
        }
        return;
    }

    /* schedule */
    if (strcmp(yn->key, "schedule") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->trigger_type != A_FN_TRIGGER_CRON) {
            YAML_ADD_ERROR(p, evt, "Invalid %s", yn->full_path);
            return;
        }

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_STRING, A_IDX_FN_NONE);
            yml_node->str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* jitter seconds */
    if (strcmp(yn->key, "jitter_seconds") == 0) {
        int32_t seconds;
        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->trigger_type != A_FN_TRIGGER_CRON) {
            YAML_ADD_ERROR(p, evt, "Invalid %s", yn->full_path);
            return;
        }

        if (aura_scan_str(yn->str_val, "%d" SCNd32, &seconds) < 0 || seconds < 0) {
            YAML_ADD_ERROR(p, evt, "Invalid %s, %d", yn->full_path, seconds);
            return;
        }

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_INT, A_IDX_FN_NONE);
            yml_node->int_val = seconds;
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* misfire policy */
    if (strcmp(yn->key, "misfire_policy") == 0) {
        aura_fn_cron_misfire_policy_t policy;

        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->trigger_type != A_FN_TRIGGER_CRON) {
            YAML_ADD_ERROR(p, evt, "Invalid %s", yn->full_path);
            return;
        }

        if (!aura_fn_validate_misfire_policy(yn->str_val, &policy)) {
            YAML_ADD_ERROR(p, evt, "Invalid %s", yn->full_path);
            return;
        }

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_INT, A_IDX_FN_NONE);
            yml_node->int_val = policy;
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* Retry */
    if (strcmp(yn->key, "retries") == 0) {
        a_ensure_node_is_mapping(p, evt, yn);

        if (usr_data->trigger_type != A_FN_TRIGGER_CRON) {
            YAML_ADD_ERROR(p, evt, "Invalid %s", yn->full_path);
            return;
        }

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_NONE, A_IDX_FN_CRON_RETRIES);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* retry on */
    if (strcmp(yn->key, "retry_on") == 0) {
        /**/
    }
}

/* Concurrency */
void a_fn_validate_concurrency(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_yml_node *yn) {
    struct aura_yml_fn_data_ctx *usr_data;
    aura_rax_tree_t *rax;
    uint32_t node_off;
    struct aura_yml_node *yml_node;
    int res;

    usr_data = (struct aura_yml_fn_data_ctx *)p->usr_data_ctx;
    rax = &usr_data->parse_tree;

    if (!yn) {
        app_alert(true, 0, "Validation node not passed: fix asap");
        return;
    }

    if (usr_data->extract && !rax) {
        app_alert(true, 0, "Trying to extract data without parser tree!: fix asap");
        return;
    }

    if (strcmp(yn->key, "concurrency") == 0) {
        a_ensure_node_is_mapping(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_NONE, A_IDX_FN_CONCURRENCY);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* Min/Max instances */
    if (strcmp(yn->key, "min_instances") == 0 || strcmp(yn->key, "max_instances") == 0) {
        int instances;
        bool is_max;

        if (strcmp(yn->key, "min_instances") == 0)
            is_max == false;
        else
            is_max = true;

        a_ensure_node_is_scalar(p, evt, yn);
        res = aura_scan_str(yn->str_val, "%d" SCNi32, &instances);
        if (is_max) {
            if (res < 0 || res > INT32_MAX) {
                /** @todo: define max instances */
                YAML_ADD_ERROR(p, evt, "Invalid %s, Maximum value is %d", yn->full_path, INT32_MAX);
            }
        } else {
            if (res != 1 || res < 1) {
                YAML_ADD_ERROR(p, evt, "Invalid %s, Minimum value is 1", yn->full_path);
            }
        }

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(
              yml_node,
              yn->type,
              yn->key,
              A_YAML_INT,
              is_max ? A_IDX_FN_MAX_INSTANCES : A_IDX_FN_MIN_INSTANCES);
            yml_node->int_val = instances;
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    if (strcmp(yn->key, "pre_warm_on_deploy") == 0) {
        int pre_warm;

        a_ensure_node_is_scalar(p, evt, yn);

        if (strcmp(yn->str_val, "true") == 0) {
            pre_warm = true;
        } else if (strcmp(yn->str_val, "false") == 0) {
            pre_warm = false;
        } else {
            YAML_ADD_ERROR(p, evt, "Invalid %s", yn->full_path);
            return;
        }

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_BOOL, A_IDX_FN_PREWARM);
            yml_node->bool_val = pre_warm;
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }
}

bool aura_fn_validate_oom_policy(const char *policy, int *value) {
    if (strcmp(policy, "throttle") == 0) {
        *value = THROTTLE;
        return true;
    }

    if (strcmp(policy, "kill") == 0) {
        *value = KILL;
        return true;
    }

    if (strcmp(policy, "snaphost_then_kill") == 0) {
        *value = SNAPSHOT_THEN_KILL;
        return true;
    }

    return false;
}

/** Resources */
void a_fn_validate_resource(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_yml_node *yn) {
    struct aura_yml_fn_data_ctx *usr_data;
    aura_rax_tree_t *rax;
    uint32_t node_off;
    struct aura_yml_node *yml_node;
    int res;

    usr_data = (struct aura_yml_fn_data_ctx *)p->usr_data_ctx;
    rax = &usr_data->parse_tree;

    if (!yn) {
        app_alert(true, 0, "Validation node not passed: fix asap");
        return;
    }

    if (usr_data->extract && !rax) {
        app_alert(true, 0, "Trying to extract data without parser tree!: fix asap");
        return;
    }

    if (strcmp(yn->key, "resources") == 0) {
        a_ensure_node_is_mapping(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_NONE, A_IDX_FN_RESOURCES);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    if (strcmp(yn->key, "memory") == 0) {
        a_ensure_node_is_mapping(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_NONE, A_IDX_FN_MEMORY);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    if (strcmp(yn->key, "soft") == 0 || strcmp(yn->key, "hard") == 0) {
        bool is_soft;
        int value;

        a_ensure_node_is_scalar(p, evt, yn);

        if (strcmp(yn->key, "soft") == 0)
            is_soft = true;
        else
            is_soft = false;

        if (aura_scan_str(yn->str_val, "%d" SCNu32, &value) < 0) {
            YAML_ADD_ERROR(p, evt, "Invalid %s", yn->full_path);
            return;
        }

        if (value < 0 || value > 256) {
            YAML_ADD_ERROR(p, evt, "Invalid %s", yn->full_path);
            return;
        }

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_INT, is_soft ? A_IDX_FN_SOFT_MEM : A_IDX_FN_HARD_MEM);
            yml_node->int_val = value;
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    if (strcmp(yn->key, "oom_policy") == 0) {
        int policy;

        a_ensure_node_is_scalar(p, evt, yn);

        if (!aura_fn_validate_oom_policy(yn->str_val, &policy)) {
            YAML_ADD_ERROR(p, evt, "Invalid %s", yn->str_val);
            return;
        }

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            yml_node = &usr_data->node_vec.entries[node_off];
            a_init_yaml_node(yml_node, yn->type, yn->key, A_YAML_INT, A_IDX_FN_OOM_POLICY);
            yml_node->int_val = policy;
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }
}

/**
 *
 */
struct aura_yml_validator aura_function_validator[] = {
  {"version", .cb = a_fn_validate_yaml_version},
  {"function", .cb = a_fn_validate_function},
  {"env", .cb = a_fn_validate_env},
  {"triggers", .cb = a_fn_validate_triggers},
  {"concurrency", .cb = a_fn_validate_concurrency},
  {"resources", .cb = a_fn_validate_resource},
  //   {"no_path_validator", .cb = run_parent_validator},
};

int aura_function_validator_len = ARRAY_SIZE(aura_function_validator);

/**
 *
 */
int a_fn_init_user_data_ctx(struct aura_yml_fn_data_ctx *usr_data, bool extract, int fn_dir_fd) {
    memset(usr_data, 0, sizeof(*usr_data));
    usr_data->extract = extract;
    usr_data->dir_fd = fn_dir_fd; /* function directory fd */

    if (usr_data->extract) {
        if (aura_rax_init(&usr_data->parse_tree) < 0)
            return -1;

        aura_blob_builder_init(&usr_data->builder);
    }

    return 0;
}

void a_fn_free_user_data_ctx(struct aura_yml_fn_data_ctx *usr_data) {
    if (!usr_data)
        return;

    for (int i = 0; i < usr_data->node_vec.cnt; ++i) {
        if (usr_data->node_vec.entries[i].key) {
            free((void *)usr_data->node_vec.entries[i].key);
        }
        if (usr_data->node_vec.entries[i].str_val && usr_data->node_vec.entries[i].val_type == A_YAML_STRING) {
            free((void *)usr_data->node_vec.entries[i].str_val);
        }
    }

    if (usr_data->extract) {
        aura_rax_free(&usr_data->parse_tree);
        aura_blob_free(&usr_data->builder);
    }

    if (usr_data->node_vec.entries)
        free(usr_data->node_vec.entries);
}

/**
 *
 */
void aura_dmn_validate_fn_conf(int conf_fd, int cli_fd) {
    struct aura_yml_fn_data_ctx usr_data;
    struct aura_yml_err_ctx *parser_err;
    bool fail_fast = true, extract = false;
    int res;
    const char *first_err = NULL;

    parser_err = aura_create_yml_error_ctx(fail_fast);
    /* we don't have the dir fd when validating, so we just pass -1 */
    if (a_fn_init_user_data_ctx(&usr_data, extract, -1) < 0) {
        aura_resp_send(cli_fd, (void *)fn_config_valid, sizeof(fn_config_valid) - 1);
        return;
    }

    res = aura_load_config_fd(conf_fd, aura_function_validator, aura_function_validator_len, parser_err, (void *)&usr_data);
    if (res != 0 && parser_err->err_cnt > 0) {
        first_err = parser_err->errors[0].message;
        aura_resp_send(cli_fd, (void *)first_err, strlen(first_err));
    } else {
        aura_resp_send(cli_fd, (void *)fn_config_valid, sizeof(fn_config_valid) - 1);
    }

    close(cli_fd);
    aura_free_yml_error_ctx(parser_err);
    a_fn_free_user_data_ctx(&usr_data);
}
