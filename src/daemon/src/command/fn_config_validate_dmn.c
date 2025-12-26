#include "blobber_lib.h"
// #include "command/function_dmn.h"
#include "error_lib.h"
#include "function_lib.h"
#include "radix_lib.h"
#include "unix_socket_lib.h"
#include "utils_lib.h"
#include "yaml_lib.h"

#include <regex.h>
#include <stdio.h>

const struct aura_http_method_t_map http_methods[] = {
  {"get", GET},
  {"post", POST},
  {"put", PATCH},
  {"patch", PATCH},
  {"delete", DELETE},
  {"head", HEAD},
};

const struct aura_trigger_t_map trigger_types[] = {
  {"http", A_TRIGGER_HTTP},
  {"cron", A_TRIGGER_CRON},
  {"queue", A_TRIGGER_QUEUE},
};

const struct aura_runtime_t_map runtimes[] = {
  {"js", JIT},
  {"native", NATIVE},
  {"wasm", WASM},
};

const struct aura_protocol_t_map protocols[] = {
  {"tcp", TCP},
  {"udp", UDP},
};

const struct aura_log_level_t_map log_levels[] = {
  {"trace", TRACE},
  {"info", INFO},
  {"debug", DEBUG},
  {"warn", WARN},
  {"error", ERROR},
};

const struct aura_oom_policy_t_map oom_policies[] = {
  {"kill", KILL},
  {"snapshot_then_kill", SNAPSHOT_THEN_KILL},
  {"throttle", THROTTLE},
};

const struct aura_log_redact_level_t_map log_redact_levels[] = {
  {"pii", PII_DEFAULT},
  {"strict", REDACT_STRICT},
  {"none", REDACT_NONE},
};

const struct aura_deployment_strategy_t_map deploy_strategies[] = {
  {"canary", CANARY},
  {"blue_green", BLUE_GREEN},
  {"rolling", ROLLING},
};

const struct aura_blue_green_t_map blue_green_opt[] = {
  {"blue", BLUE},
  {"green", GREEN},
};

const struct aura_backoff_t_map backoff_opt[] = {
  {"none", BACKOFF_NONE},
  {"fixed", BACKOFF_FIXED},
  {"exponential", BACKOFF_EXPONENTIAL},
};

const struct aura_cron_misfire_policy_t_map misfire_policies[] = {
  {"fire_now", FIRE_NOW},
  {"ignore", IGNORE},
  {"reschedule", RESCHEDULE},
};

const struct aura_network_policy_t_map network_policies[] = {
  {"allow_all", ALLOW_ALL},
  {"deny_all", DENY_ALL},
  {"whitelist", WHITELIST},
};

void aura_function_dump(struct aura_fn *fn) {
    app_debug(true, 0, "Aura function:");
    app_debug(true, 0, "   fn id => %ld", fn->fn_id);
    app_debug(true, 0, "   fn name => %p", fn->name);
    app_debug(true, 0, "   fn desc => %p", fn->description);
    app_debug(true, 0, "   fn version => %p", fn->version);
    // app_debug(true, 0, "   fn runtime => %d", fn->runtime);
    app_debug(true, 0, "   fn entry point => %p", fn->entry_point);

    app_debug(true, 0, "   Fn Triggers HTTP:");
    app_debug(true, 0, "       fn trigger http path => %p", fn->http_trigger.path.base);
    app_debug(true, 0, "       fn trigger http method => %p", fn->http_trigger.http_method);
    app_debug(true, 0, "       fn trigger http auth => %p", fn->http_trigger.auth);

    app_debug(true, 0, "   Fn Trigger CRON:");
    app_debug(true, 0, "       fn trigger cron schedule => %p", fn->cron_trigger.cron_schedule);
    app_debug(true, 0, "       fn trigger cron jitter_seconds => %d", fn->cron_trigger.jitter_seconds);
    app_debug(true, 0, "       fn trigger cron misfire policy => %d", fn->cron_trigger.misfire_policy);
    app_debug(true, 0, "       fn trigger cron max concurrency => %p", fn->cron_trigger.max_concurrent);
    app_debug(true, 0, "       Retry:");
    app_debug(true, 0, "           retry attempts => %d", fn->cron_trigger.retry.attempts);
    app_debug(true, 0, "           retry policy => %d", fn->cron_trigger.retry.poilcy);
    app_debug(true, 0, "           retry on => %d", fn->cron_trigger.retry.retry_on);
    app_debug(true, 0, "           retry dead letter => %d", fn->cron_trigger.retry.dead_letter);
    app_debug(true, 0, "           retry window exec count => %d", fn->cron_trigger.retry.wind_exec.count);
    app_debug(true, 0, "           retry window exec start => %ld", fn->cron_trigger.retry.wind_exec.window.start);
    app_debug(true, 0, "           retry window exec end => %ld", fn->cron_trigger.retry.wind_exec.window.end);

    app_debug(true, 0, "   Fn Trigger Queue:");
    // app_debug(true, 0, "       fn trigger queue topic => %p", fn->queue_trigger.topic);
    // app_debug(true, 0, "       fn trigger queue topic => %d", fn->queue_trigger.per_key_concurrency);
    app_debug(true, 0, "   fn last execution time => %ld", fn->last_execution);

    app_debug(true, 0, "   Fn Resources:");
    app_debug(true, 0, "       fn cpu share => %d", fn->fn_resources.cpu_shares);
    app_debug(true, 0, "       fn cpu burst credit => %d", fn->fn_resources.cpu_burst_credit);
    app_debug(true, 0, "       fn cpu mem limit hard => %d", fn->fn_resources.memory_limit_mb_hard);
    app_debug(true, 0, "       fn cpu mem limit soft => %d", fn->fn_resources.memory_limit_mb_soft);
    app_debug(true, 0, "       fn out of memory => %d", fn->fn_resources.oom_pol);
    app_debug(true, 0, "       fn timeout => %d", fn->fn_resources.timeout);
    app_debug(true, 0, "       fn io_net_egress_bytes_per_sec => %d", fn->fn_resources.io_net_egress_bytes_per_sec);
    app_debug(true, 0, "       fn socket max => %d", fn->fn_resources.socket_max);

    app_debug(true, 0, "   Fn Concurrency:");
    app_debug(true, 0, "       fn max instances => %d", fn->fn_concurrency.max_instances);
    app_debug(true, 0, "       fn pre warn on deploy => %p", fn->fn_concurrency.pre_warm_on_deploy);
    app_debug(true, 0, "       fn delay => %d", fn->fn_concurrency.delay);
    app_debug(true, 0, "       fn background task => %p", fn->fn_concurrency.background_tasks);

    app_debug(true, 0, "   Fn Networking:");
    app_debug(true, 0, "       Ingress:");
    app_debug(true, 0, "           fn ingress policy => %d", fn->networking.inbound.policy);
    for (int i = 0; i < fn->networking.inbound.whitelsit_len; ++i)
        app_debug(true, 0, "           fn ingress whitelist[%i] => %p", fn->networking.inbound.ip_whitelist[i]);

    app_debug(true, 0, "       Egress:");
    app_debug(true, 0, "           fn egress policy => %d", fn->networking.outbound.policy);
    for (int i = 0; i < fn->networking.outbound.whitelist_len; ++i) {
        app_debug(true, 0, "           fn ingress whitelist[%i] host => %p", fn->networking.outbound.hosts[i]->host);
        app_debug(true, 0, "           fn ingress whitelist[%i] port => %d", fn->networking.outbound.hosts[i]->port);
        app_debug(true, 0, "           fn ingress whitelist[%i] protocol => %d", fn->networking.outbound.hosts[i]->protocol);
        app_debug(true, 0, "           fn ingress whitelist[%i] protocol version => %d", fn->networking.outbound.hosts[i]->prot_version);
        app_debug(true, 0, "           fn ingress whitelist[%i] secure(https) => %d", fn->networking.outbound.hosts[i]->secure);
        app_debug(true, 0, "           fn ingress whitelist[%i] max per origin => %d", fn->networking.outbound.hosts[i]->max_per_origin);
        app_debug(true, 0, "           fn ingress whitelist[%i] idle_ttl => %d", fn->networking.outbound.hosts[i]->idle_ttl);
        app_debug(true, 0, "           ");
    }

    app_debug(true, 0, "   Observability:");
    app_debug(true, 0, "       custom metrics => %d", fn->fn_observability.custom_metrics);
    app_debug(true, 0, "       Logging:");
    app_debug(true, 0, "           Destination => %p", fn->fn_observability.fn_logging.destination);
    app_debug(true, 0, "           Log level => %d", fn->fn_observability.fn_logging.level);
    app_debug(true, 0, "           Log redact => %d", fn->fn_observability.fn_logging.log_redact);
    app_debug(true, 0, "       Tracing:");
    app_debug(true, 0, "           Enabled => %d", fn->fn_observability.fn_tracing.enabled);
    app_debug(true, 0, "           Sample rate => %d", fn->fn_observability.fn_tracing.sample_rate);
    app_debug(true, 0, "           Tail sampling rate => %d", fn->fn_observability.fn_tracing.tail_sampling_target_ms);

    app_debug(true, 0, "   Environment:");

    app_debug(true, 0, "   Batch processing:");
    app_debug(true, 0, "       ms => %d", fn->publish_batch_ms);
}

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

    if (us->node_cnt >= us->node_cap) {
        us->node_cap = us->node_cap < 5 ? 5 : us->node_cap * 2;
        us->node_arr = realloc(us->node_arr, us->node_cap * sizeof(struct aura_yml_node));
        if (!us->node_arr) {
            YAML_ADD_ERROR(p, evt, "Out of memory");
            return UINT32_MAX;
        }
    }
    memset(&(us->node_arr[us->node_cnt]), 0, sizeof(struct aura_yml_node));
    return us->node_cnt++;
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
    t = us->parse_tree;

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

/* ------------------------------------------ */
/*----------- AURA YAML VERSION -----------*/
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

/*----------- FUNCTION ---------- */
void a_fn_validate_function(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_yml_node *yn) {
    struct aura_yml_fn_data_ctx *usr_data;
    aura_rax_tree_t *rax;
    uint32_t node_off;
    int res;

    usr_data = (struct aura_yml_fn_data_ctx *)p->usr_data_ctx;
    rax = usr_data->parse_tree;

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
            usr_data->node_arr[node_off].type = yn->type;
            usr_data->node_arr[node_off].key = strdup(yn->key);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* FN name */
    if (strcmp(yn->key, "name") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_FN_NAME);
            usr_data->node_arr[node_off].str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* FN description */
    if (strcmp(yn->key, "description") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_FN_DESCRIPTION);
            usr_data->node_arr[node_off].str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* FN version */
    if (strcmp(yn->key, "version") == 0) {
        int version;
        a_ensure_node_is_scalar(p, evt, yn);

        res = aura_scan_str(yn->str_val, "%" SCNu32, &version);
        if (res != 1 || version > UINT32_MAX)
            YAML_ADD_ERROR(p, evt, "Invalid %s, Expected a valid version number", yn->full_path);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NUM, A_IDX_FN_VERSION);
            usr_data->node_arr[node_off].int_val = version;
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
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_FN_VERSION);
            usr_data->node_arr[node_off].str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* FN host @todo: could be better */
    if (strcmp(yn->key, "host") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_FN_HOST);
            usr_data->node_arr[node_off].str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* FN env vars */
    if (strcmp(yn->key, "env") == 0) {
        a_ensure_node_is_sequence(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NONE, A_IDX_FN_ENV);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* FN env[*] */
    if (strcmp(yn->key, "env[*]") == 0) {
        a_ensure_node_is_mapping(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NONE, A_IDX_FN_NONE);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* env[*].name */
    if (strcmp(yn->key, "name") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_FN_VERSION);
            usr_data->node_arr[node_off].str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* env[*].value */
    if (strcmp(yn->key, "value") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_FN_VERSION);
            usr_data->node_arr[node_off].str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }
}

/* Triggers */
void a_fn_validate_triggers(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_yml_node *yn) {
    struct aura_yml_fn_data_ctx *usr_data;
    aura_rax_tree_t *rax;
    uint32_t node_off;
    int res;

    usr_data = (struct aura_yml_fn_data_ctx *)p->usr_data_ctx;
    rax = usr_data->parse_tree;

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
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NONE, A_IDX_FN_TRIGGERS);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* trigger http */
    if (strcmp(yn->key, "http") == 0) {
        a_ensure_node_is_mapping(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_FN_HTTP_TRIGGER);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* trigger type (http) path */
    if (strcmp(yn->key, "path") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);
        // ensure http is the trigger type
        // maybe use regex for a stronger check

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_FN_NONE);
            usr_data->node_arr[node_off].str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* trigger type(http) method */
    if (strcmp(yn->key, "method") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);
        // ensure http is the trigger type

        /* add other method comparisons */
        if (strcasecmp(yn->str_val, "GET") != 0 && strcasecmp(yn->str_val, "POST") != 0) {
            YAML_ADD_ERROR(p, evt, "Unexpected method %s, expected one of GET/get, POST/post + others", yn->str_val);
        }

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_FN_NONE);
            usr_data->node_arr[node_off].str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }
}

/* Concurrency */
void a_fn_validate_concurrency(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_yml_node *yn) {
    struct aura_yml_fn_data_ctx *usr_data;
    aura_rax_tree_t *rax;
    uint32_t node_off;
    int res;

    usr_data = (struct aura_yml_fn_data_ctx *)p->usr_data_ctx;
    rax = usr_data->parse_tree;

    if (!yn) {
        app_alert(true, 0, "Validation node not passed: fix asap");
        return;
    }

    if (usr_data->extract && !rax) {
        app_alert(true, 0, "Trying to extract data without parser tree!: fix asap");
        return;
    }

    /* Min instances */
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
            if (res != 1 || res > INT32_MAX) {
                /** @todo: define max instances */
                YAML_ADD_ERROR(p, evt, "Invalid %s, Maximum value is %d", yn->full_path, INT32_MAX);
            }
        } else {
            if (res != 1 || res < 1) {
                YAML_ADD_ERROR(p, evt, "Invalid %s, Minimum value is 1", yn->full_path);
            }
        }

        if (usr_data->extract && !!p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NUM, is_max ? A_IDX_FN_MAX_INSTANCES : A_IDX_FN_MIN_INSTANCES);
            usr_data->node_arr[node_off].int_val = instances;
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
  {"triggers", .cb = a_fn_validate_triggers},
  {"concurrency", .cb = a_fn_validate_concurrency},
  //   {"no_path_validator", .cb = run_parent_validator},
};

int aura_function_validator_len = ARRAY_SIZE(aura_function_validator);

/**
 *
 */
void a_fn_init_user_data_ctx(struct aura_yml_fn_data_ctx *usr_data, bool extract, int fn_dir_fd) {
    memset(usr_data, 0, sizeof(*usr_data));
    usr_data->extract = extract;
    usr_data->dir_fd = fn_dir_fd; /* function directory fd */

    if (usr_data->extract) {
        usr_data->parse_tree = aura_rax_new();
        aura_blob_builder_init(&usr_data->builder);
    }
}

void a_fn_free_user_data_ctx(struct aura_yml_fn_data_ctx *usr_data) {
    if (!usr_data)
        return;

    for (int i = 0; i < usr_data->node_cnt; ++i) {
        if (usr_data->node_arr[i].key) {
            free((void *)usr_data->node_arr[i].key);
        }
        if (usr_data->node_arr[i].str_val && usr_data->node_arr[i].val_type == A_YAML_STRING) {
            free((void *)usr_data->node_arr[i].str_val);
        }
    }

    if (usr_data->parse_tree)
        aura_rax_free(usr_data->parse_tree);

    if (usr_data->extract)
        aura_blob_free(&usr_data->builder);

    if (usr_data->node_arr)
        free(usr_data->node_arr);
}

/**
 *
 */
void aura_dmn_function_config_validate(int conf_fd, int cli_fd) {
    struct aura_yml_fn_data_ctx usr_data;
    struct aura_yml_err_ctx *parser_err;
    bool fail_fast = true, extract = false;
    int res;
    const char *first_err = NULL;

    parser_err = aura_create_yml_error_ctx(fail_fast);
    /* we don't have the dir fd when validating, so we just pass -1 */
    a_fn_init_user_data_ctx(&usr_data, extract, -1);

    res = aura_load_config_fd(conf_fd, aura_function_validator, aura_function_validator_len, parser_err, (void *)&usr_data);
    if (res != 0 && parser_err->err_cnt > 0) {
        first_err = parser_err->errors[0].message;
        aura_send_resp(cli_fd, (void *)first_err, strlen(first_err));
    } else {
        aura_send_resp(cli_fd, (void *)fn_config_valid, sizeof(fn_config_valid) - 1);
    }

    close(cli_fd);
    aura_free_yml_error_ctx(parser_err);
    a_fn_free_user_data_ctx(&usr_data);
}