#include "blobber_lib.h"
#include "function_lib.h"

const struct aura_fn_runtime runtimes[] = {
  {"js", JIT},
  {"native", NATIVE},
  {"wasm", WASM},
};

const struct aura_fn_trigger trigger_types[] = {
  {"http", A_TRIGGER_HTTP},
  {"cron", A_TRIGGER_CRON},
  {"queue", A_TRIGGER_QUEUE},
};

const struct aura_fn_http_method http_methods[] = {
  {"get", GET},
  {"post", POST},
  {"put", PUT},
  {"patch", PATCH},
  {"delete", DELETE},
  {"head", HEAD},
};

const struct aura_fn_cron_misfire_policy misfire_policies[] = {
  {"fire_now", FIRE_NOW},
  {"ignore", IGNORE},
  {"reschedule", RESCHEDULE},
};

const struct aura_fn_backoff backoff_opt[] = {
  {"none", BACKOFF_NONE},
  {"fixed", BACKOFF_FIXED},
  {"exponential", BACKOFF_EXPONENTIAL},
};

const struct aura_fn_log_level log_levels[] = {
  {"trace", TRACE},
  {"info", INFO},
  {"debug", DEBUG},
  {"warn", WARN},
  {"error", ERROR},
};

const struct aura_fn_oom_policy oom_policies[] = {
  {"kill", KILL},
  {"snapshot_then_kill", SNAPSHOT_THEN_KILL},
  {"throttle", THROTTLE},
};

const struct aura_fn_log_redact_level log_redact_levels[] = {
  {"pii", PII_DEFAULT},
  {"strict", REDACT_STRICT},
  {"none", REDACT_NONE},
};

const struct aura_fn_deployment_strategy deploy_strategies[] = {
  {"canary", CANARY},
  {"blue_green", BLUE_GREEN},
  {"rolling", ROLLING},
};

const struct aura_fn_network_policy network_policies[] = {
  {"allow_all", ALLOW_ALL},
  {"deny_all", DENY_ALL},
  {"whitelist", WHITELIST},
};

int _fn_conf_tab[] = {
  [A_IDX_FN_NONE] = 0,
  [A_IDX_FN_FUNCTION] = 0,
  [A_IDX_FN_NAME] = 0,
  [A_IDX_FN_DESCRIPTION] = 0,
  [A_IDX_FN_VERSION] = 0,
  [A_IDX_FN_HOST] = 0,
  [A_IDX_FN_ENTRY_POINT] = 0,
  [A_IDX_FN_ENV] = 0,
  [A_IDX_FN_TRIGGERS] = 0,
  [A_IDX_FN_HTTP_TRIGGER] = 0,
  [A_IDX_FN_CRON_TRIGGER] = 0,
  [A_IDX_FN_QUEUE_TRIGGER] = 0,
  [A_IDX_FN_CONCURRENCY] = 0,
  [A_IDX_FN_MIN_INSTANCES] = 0,
  [A_IDX_FN_MAX_INSTANCES] = 0,
  [A_IDX_FN_PREWARM] = 0,
  [A_IDX_FN_CRON_RETRIES] = 0,
  [A_IDX_FN_RESOURCES] = 0,
  [A_IDX_FN_MEMORY] = 0,
  [A_IDX_FN_SOFT_MEM] = 0,
  [A_IDX_FN_HARD_MEM] = 0,
  [A_IDX_FN_OOM_POLICY] = 0,
  [A_IDX_FN_NETWORKING] = 0,
  [A_IDX_FN_RUNTIME] = 0,
};

size_t _fn_conf_tab_size = ARRAY_SIZE(_fn_conf_tab);

int aura_fn_meta_parse(void *meta, struct aura_fn_meta *fn_meta) {
    const st_aura_blob_node *nodes;
    const st_aura_blob_arr_entry *arrs;
    const st_aura_blob_kv_pair *kv_pairs, *kv;
    const char *strtab;
    const int *fn_tab;
    const st_aura_blob_node *kv_val_node;
    uint32_t kv_cnt, kv_idx, arr_cnt, arr_idx;
    const char *kv_key, *kv_val;

    nodes = aura_blob_get_nodes(meta);
    kv_pairs = aura_blob_get_kvs(meta);
    arrs = aura_blob_get_arrs(meta);
    strtab = aura_blob_get_strtab(meta);
    fn_tab = aura_blob_get_tab(meta);

    const st_aura_blob_node *node;

    memset(fn_meta, 0, sizeof(*fn_meta));
    /* Fn name */
    if (fn_tab[A_IDX_FN_NAME] != 0) {
        node = &nodes[fn_tab[A_IDX_FN_NAME]];
        fn_meta->name = strdup(strtab + node->str_offset);
    }

    /* Description */
    if (fn_tab[A_IDX_FN_DESCRIPTION] != 0) {
        node = &nodes[fn_tab[A_IDX_FN_DESCRIPTION]];
        fn_meta->description = strdup(strtab + node->str_offset);
    }

    /* Version */
    if (fn_tab[A_IDX_FN_VERSION] != 0) {
        const char *version;

        node = &nodes[fn_tab[A_IDX_FN_VERSION]];
        version = strtab + node->str_offset;
        if (aura_scan_str(version, "%d" SCNu32, &fn_meta->version) == 0)
            goto exception;
    }

    /* Entry */
    if (fn_tab[A_IDX_FN_ENTRY_POINT] != 0) {
        node = &nodes[fn_tab[A_IDX_FN_ENTRY_POINT]];
        fn_meta->entry_point = strdup(strtab + node->str_offset);
    }

    /* Host */
    if (fn_tab[A_IDX_FN_HOST] != 0) {
        node = &nodes[fn_tab[A_IDX_FN_HOST]];
        fn_meta->host = strdup(strtab + node->str_offset);
    }

    /* FN triggers */
    const st_aura_blob_node *fn_triggers_node, *http_trigger_node, *cron_trigger_node, *queue_trigger_node;
    const st_aura_blob_node *cron_trigger_retry_node;

    if (fn_tab[A_IDX_FN_TRIGGERS] != 0) {
        fn_triggers_node = &nodes[fn_tab[A_IDX_FN_TRIGGERS]];
        /* http */
        if (fn_tab[A_IDX_FN_HTTP_TRIGGER] != 0) {
            http_trigger_node = &nodes[fn_tab[A_IDX_FN_HTTP_TRIGGER]];
            kv_idx = http_trigger_node->map.kv_idx;
            kv_cnt = http_trigger_node->map.kv_cnt;

            for (int i = 0; i < kv_cnt; ++i) {
                kv = &kv_pairs[kv_idx + i];
                kv_val_node = &nodes[kv->node_idx];
                kv_key = strtab + kv->key_offset;

                if (strcmp(kv_key, "path") == 0) {
                    kv_val = strtab + kv_val_node->str_offset;
                    fn_meta->http_trigger.path.base = strdup(kv_val);
                    fn_meta->http_trigger.path.len = strlen(kv_val);
                }

                if (strcmp(kv_key, "method") == 0) {
                    kv_val = strtab + kv_val_node->str_offset;
                    fn_meta->http_trigger.http_method = aura_fn_http_method_get(kv_val);
                    if (!fn_meta->http_trigger.http_method) {
                        goto exception;
                    }
                }

                if (strcmp(kv_key, "auth") == 0) {
                    /**/
                }
            }
        }

        /* Cron trigger */
        if (fn_tab[A_IDX_FN_CRON_TRIGGER] != 0) {
            cron_trigger_node = &nodes[fn_tab[A_IDX_FN_CRON_TRIGGER]];
            kv_idx = cron_trigger_node->map.kv_idx;
            kv_cnt = cron_trigger_node->map.kv_cnt;

            for (int i = 0; i < kv_cnt; ++i) {
                kv = &kv_pairs[kv_idx + i];
                kv_val_node = &nodes[kv->node_idx];
                kv_key = strtab + kv->key_offset;

                if (strcmp(kv_key, "schedule") == 0) {
                    kv_val = strtab + kv_val_node->str_offset;
                    fn_meta->cron_trigger.cron_schedule = strdup(kv_val);
                }

                if (strcmp(kv_key, "jitter_seconds") == 0) {
                    kv_val = strtab + kv_val_node->str_offset;
                    if (aura_scan_str(kv_val, "%d" SCNu64, &fn_meta->cron_trigger.jitter_seconds) == 0)
                        goto exception;
                }

                if (strcmp(kv_key, "misfire_policy") == 0) {
                    kv_val = strtab + kv_val_node->str_offset;
                    fn_meta->cron_trigger.misfire_policy = aura_fn_cron_misfire_policy_get(kv_val);
                    if (!fn_meta->cron_trigger.misfire_policy)
                        goto exception;
                }

                if (fn_tab[A_IDX_FN_CRON_RETRIES] != 0) {
                    cron_trigger_retry_node = &nodes[fn_tab[A_IDX_FN_CRON_RETRIES]];
                }
            }
        }

        /* Queue trigger */
        if (fn_tab[A_IDX_FN_QUEUE_TRIGGER] != 0) {
            queue_trigger_node = &nodes[fn_tab[A_IDX_FN_QUEUE_TRIGGER]];
            kv_idx = cron_trigger_node->map.kv_idx;
            kv_cnt = cron_trigger_node->map.kv_cnt;

            for (int i = 0; i < kv_cnt; ++i) {
                kv = &kv_pairs[kv_idx + i];
                kv_val_node = &nodes[kv->node_idx];
                kv_key = strtab + kv->key_offset;

                if (strcmp(kv_key, "topic") == 0) {
                    kv_val = strtab + kv_val_node->str_offset;
                }
            }
        }
    }

    /* Fn memory */
    const st_aura_blob_node *memory_node;
    if (fn_tab[A_IDX_FN_MEMORY] != 0) {
        memory_node = &nodes[fn_tab[A_IDX_FN_MEMORY]];
        kv_idx = memory_node->map.kv_idx;
        kv_cnt = memory_node->map.kv_cnt;

        for (int i = 0; i < kv_cnt; ++i) {
            kv = &kv_pairs[kv_idx + i];
            kv_val_node = &nodes[kv->node_idx];
            kv_key = strtab + kv->key_offset;

            if (strcmp(kv_key, "soft") == 0) {
                kv_val = strtab + kv_val_node->str_offset;
                if (aura_scan_str(kv_val, "%u" SCNu32, &fn_meta->fn_resources.memory_limit_mb_soft) == 0)
                    goto exception;
            }

            if (strcmp(kv_key, "hard") == 0) {
                kv_val = strtab + kv_val_node->str_offset;
                if (aura_scan_str(kv_val, "%u" SCNu32, &fn_meta->fn_resources.memory_limit_mb_hard) == 0)
                    goto exception;
            }

            if (strcmp(kv_key, "oom_policy") == 0) {
                kv_val = strtab + kv_val_node->str_offset;
                fn_meta->fn_resources.oom_policy = aura_fn_oom_policy_get(kv_val);
                if (!fn_meta->fn_resources.oom_policy)
                    goto exception;
            }
        }
    }

    if (fn_tab[A_IDX_FN_NETWORKING] != 0) {
        /**/
    }

    return 0;

exception:
    aura_fn_meta_destroy(fn_meta);
    return 1;
}

int aura_fn_config_parse(void *config, struct aura_fn_config *fn_config) {
    const st_aura_blob_node *nodes;
    const st_aura_blob_arr_entry *arrs;
    const st_aura_blob_kv_pair *kv_pairs, *kv;
    const char *strtab;
    const int *fn_tab;
    const st_aura_blob_node *kv_val_node;
    uint32_t kv_cnt, kv_idx, arr_cnt, arr_idx;
    const char *kv_key, *kv_val;

    nodes = aura_blob_get_nodes(config);
    kv_pairs = aura_blob_get_kvs(config);
    arrs = aura_blob_get_arrs(config);
    strtab = aura_blob_get_strtab(config);
    fn_tab = aura_blob_get_tab(config);

    memset(fn_config, 0, sizeof(*fn_config));

    const st_aura_blob_node *env_node;

    /* Envs */
    if (fn_tab[A_IDX_FN_ENV] != 0) {
        int i;

        env_node = &nodes[fn_tab[A_IDX_FN_ENV]];
        kv_cnt = env_node->map.kv_cnt;
        kv_idx = env_node->map.kv_idx;

        fn_config->envs = malloc((kv_cnt + 1) * sizeof(struct aura_iovec)); /* Null aura_iovec terminated */
        if (!fn_config->envs)
            goto exception;

        for (i = 0; i < kv_cnt; ++i) {
            kv = &kv_pairs[kv_idx + i];
            kv_key = strtab + kv->key_offset;
            kv_val_node = &nodes[kv->node_idx];

            fn_config->envs[i].base = strdup(strtab + kv_val_node->str_offset);
            fn_config->envs[i].len = strlen(fn_config->envs[i].base);
        }
        /* Terminate */
        fn_config->envs[i].base = NULL;
        fn_config->envs[i].len = 0;
    }

    const st_aura_blob_node *min_instance_node, *max_instance_node;

    if (fn_tab[A_IDX_FN_CONCURRENCY] != 0) {
        const char *instances;

        if (fn_tab[A_IDX_FN_MIN_INSTANCES] != 0) {
            min_instance_node = &nodes[fn_tab[A_IDX_FN_MIN_INSTANCES]];
            instances = strtab + min_instance_node->str_offset;
            if (aura_scan_str(instances, "%d" SCNu32, &fn_config->fn_concurrency.min_instances) == 0) {
                goto exception;
            }
        }

        if (fn_tab[A_IDX_FN_MAX_INSTANCES] != 0) {
            max_instance_node = &nodes[fn_tab[A_IDX_FN_MAX_INSTANCES]];
            instances = strtab + max_instance_node->str_offset;
            if (aura_scan_str(instances, "%d" SCNu32, &fn_config->fn_concurrency.max_instances) == 0)
                goto exception;
        }

        if (fn_tab[A_IDX_FN_PREWARM] != 0) {
            max_instance_node = &nodes[fn_tab[A_IDX_FN_PREWARM]];
            instances = strtab + max_instance_node->str_offset;
            if (aura_scan_str(instances, "%d" SCNu32, &fn_config->fn_concurrency.pre_warm_on_deploy) == 0)
                goto exception;
        }
    }

    /* Runtime */
    const st_aura_blob_node *runtime_node;

    if (fn_tab[A_IDX_FN_RUNTIME] != 0) {
        runtime_node = &nodes[fn_tab[A_IDX_FN_RUNTIME]];
        kv_cnt = runtime_node->map.kv_cnt;
        kv_idx = runtime_node->map.kv_idx;

        for (int i = 0; i < kv_cnt; ++i) {
            kv = &kv_pairs[kv_idx + i];
            kv_key = strtab + kv->key_offset;
            kv_val_node = &nodes[kv->node_idx];

            if (strcmp(kv_key, "active") == 0) {
                kv_val = strtab + kv_val_node->str_offset;
                fn_config->is_active = strcmp(kv_val, "true") == 0 ? true : false;
            }
        }
    }

    return 0;
exception:
    aura_fn_config_destroy(fn_config);
    return 1;
}

void aura_fn_meta_destroy(const struct aura_fn_meta *fn_meta) {
    if (fn_meta->name)
        free((char *)fn_meta->name);
    if (fn_meta->description)
        free((char *)fn_meta->description);
    if (fn_meta->host)
        free((char *)fn_meta->host);
    if (fn_meta->entry_point)
        free((char *)fn_meta->entry_point);

    aura_fn_resources_destroy(&fn_meta->fn_resources);

    aura_fn_http_trigger_destroy(&fn_meta->http_trigger);

    aura_fn_cron_trigger_destroy(&fn_meta->cron_trigger);

    aura_fn_networking_destroy(&fn_meta->networking);
}

void aura_fn_config_destroy(struct aura_fn_config *fn_config) {
    if (!fn_config)
        return;

    if (fn_config->envs) {
        for (int i = 0; fn_config->envs[i].base != NULL; ++i) {
            free(fn_config->envs[i].base);
        }
        free(fn_config->envs);
    }
}

void aura_fn_resources_destroy(const struct aura_fn_resources *resources) {
    if (!resources)
        return;
    /**/
}

void aura_fn_http_trigger_destroy(const struct aura_fn_http_trigger *http_trigger) {
    if (!http_trigger)
        return;

    if (http_trigger->path.base)
        free(http_trigger->path.base);
}

void aura_fn_cron_trigger_destroy(const struct aura_fn_cron_trigger *cron_trigger) {
    if (!cron_trigger)
        return;

    if (cron_trigger->cron_schedule)
        free((void *)cron_trigger->cron_schedule);
}

void aura_fn_networking_destroy(const void *networking) {
    if (!networking)
        return;
    /**/
}

void aura_fn_meta_dump(struct aura_fn_meta *fn_conf) {
    /**/
}

void aura_fn_config_dump(struct aura_fn_config *fn_conf) {
    app_debug(true, 0, "Aura FN CONFIG");
    app_debug(true, 0, "    Active: %s", fn_conf->is_active ? "Yes" : "No");
    app_debug(true, 0, "    Concurrency:");
    app_debug(true, 0, "        Mix instances: %d", fn_conf->fn_concurrency.min_instances);
    app_debug(true, 0, "        Max instances: %d", fn_conf->fn_concurrency.max_instances);
    app_debug(true, 0, "        Pre warn on deploy: %d", fn_conf->fn_concurrency.pre_warm_on_deploy);
    app_debug(true, 0, "        Delay: %zu", fn_conf->fn_concurrency.delay);
    app_debug(true, 0, "        Background task: %d", fn_conf->fn_concurrency.background_tasks);

    app_debug(true, 0, "    Observability:");
    app_debug(true, 0, "        Custom metrics: %d", fn_conf->fn_observability.custom_metrics);
    app_debug(true, 0, "        Logging:");
    app_debug(true, 0, "            Destination: %s", fn_conf->fn_observability.fn_logging.destination);
    app_debug(true, 0, "            Log level: %d", fn_conf->fn_observability.fn_logging.level);
    app_debug(true, 0, "            Log redact: %d", fn_conf->fn_observability.fn_logging.log_redact);
    app_debug(true, 0, "        Tracing:");
    app_debug(true, 0, "            Enabled: %d", fn_conf->fn_observability.fn_tracing.enabled);
    app_debug(true, 0, "            Sample rate: %d", fn_conf->fn_observability.fn_tracing.sample_rate);
    app_debug(true, 0, "            Tail sampling rate: %d", fn_conf->fn_observability.fn_tracing.tail_sampling_target_ms);
}

void aura_fn_evt_response_dump(struct aura_fn_evt *evt) {
    app_debug(true, 0, "AURA FN EVT RESPONSE");
    app_debug(true, 0, "    State: %u", evt->state);
    app_debug(true, 0, "    Error: %d", evt->error_code);
    app_debug(true, 0, "    Msg Len: %d", evt->msg_len);
    app_debug(true, 0, "    Message: %s", evt->msg);
}