#include "blobber/lib.h"
#include "db/broker.h"
#include "fn/lib.h"

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
};

size_t _fn_conf_tab_size = ARRAY_SIZE(_fn_conf_tab);

struct aura_functions *aura_fn_list_fetch(AURA_DBHANDLE db, int *error) {
    struct aura_functions *fns;
    struct aura_db_rec rec;
    struct aura_iovec key;
    int res;

    key = a_function_list_key;
    res = aura_db_record_fetch(db, A_DB_NS_FN, A_DB_SCHEMA_FNS, &key, &rec);
    if (res < 0 || res == A_DB_REC_NOT_FOUND) {
        *error = res;
        return NULL;
    }

    fns = (struct aura_functions *)rec.data.base;
    fns->funcs = (struct aura_fn_petite *)((char *)fns + sizeof(*fns));
    return fns;
}

struct aura_functions *aura_fn_list_fetch_broker(struct aura_mem_ctx *mc, int dmn_sock_fd, int *error) {
    struct aura_functions *fns;
    struct aura_iovec key, data_out;
    int res;

    app_debug(true, 0, "aura_fn_list_fetch_broker <<<");
    key = a_function_list_key;
    res = aura_db_broker_fetch(mc, A_DB_NS_FN, A_DB_SCHEMA_FNS, &key, &data_out, dmn_sock_fd);
    if (res < 0) {
        *error = res;
        return NULL;
    }

    fns = (struct aura_functions *)data_out.base;
    fns->funcs = (struct aura_fn_petite *)((char *)fns + sizeof(*fns));
    return fns;
}

int aura_fn_list_add(AURA_DBHANDLE db, struct aura_mem_ctx *mc, const char *fn_name,
                     uint32_t fn_version, uint64_t job_id, struct aura_db_completion *comp) {
    struct aura_functions *fns;
    struct aura_iovec key;
    struct aura_iovec *key_ptr, *data_ptr;
    size_t fns_len;
    int res, rv, error;

    key = a_function_list_key;
    fns = aura_fn_list_fetch(db, &error);
    if (!fns) {
        if (error < 0)
            return error;

        /* Record does not exist yet, create one */
        fns_len = sizeof(*fns) + sizeof(struct aura_fn_petite);

        key_ptr = aura_iovec_init(mc, key.len, NULL);
        if (!key_ptr)
            return -1;

        data_ptr = aura_iovec_init(mc, fns_len, NULL);
        if (!data_ptr) {
            aura_iovec_destroy(key_ptr);
            return -1;
        }

        memcpy(key_ptr->base, key.base, key.len);
        fns = (struct aura_functions *)data_ptr->base;
        fns->funcs = (struct aura_fn_petite *)(data_ptr->base + sizeof(*fns));
        memcpy(fns->funcs[0].fn_name, fn_name, A_FN_NAME_MAX_LEN);
        fns->funcs[0].fn_version = fn_version;
        fns->funcs[0].job_id = job_id;
        fns->func_cnt = 1;

        res = aura_db_record_insert(
          db,
          A_DB_NS_FN,
          A_DB_SCHEMA_FNS,
          job_id,
          0,
          A_DB_OP_INSERT,
          key_ptr,
          data_ptr,
          A_DB_EXEC_ASYNC,
          comp);
        if (res != 0) {
            aura_iovec_destroy(key_ptr);
            aura_iovec_destroy(data_ptr);
            return -1;
        }

        return 0;
    }

    /* Increase function count */
    fns_len = sizeof(*fns) + (sizeof(struct aura_fn_petite) * (fns->func_cnt + 1));
    key_ptr = aura_iovec_init(mc, key.len, NULL);
    if (!key_ptr) {
        rv = -1;
        goto out;
    }

    data_ptr = aura_iovec_init(mc, fns_len, NULL);
    if (!data_ptr) {
        aura_iovec_destroy(key_ptr);
        rv = -1;
        goto out;
    }

    memcpy(key_ptr->base, key.base, key.len);
    memcpy(data_ptr->base, fns, fns_len - sizeof(struct aura_functions));

    struct aura_functions *fns_ptr;

    fns_ptr = (struct aura_functions *)data_ptr->base;
    fns_ptr->funcs = (struct aura_fn_petite *)(data_ptr->base + sizeof(*fns_ptr));
    memcpy(fns_ptr->funcs[fns_ptr->func_cnt].fn_name, fn_name, A_FN_NAME_MAX_LEN);
    fns_ptr->funcs[fns_ptr->func_cnt].fn_version = fn_version;
    fns_ptr->funcs[fns_ptr->func_cnt].job_id = job_id;
    fns_ptr->func_cnt++;

    res = aura_db_record_insert(
      db,
      A_DB_NS_FN,
      A_DB_SCHEMA_FNS,
      job_id,
      0,
      A_DB_OP_INSERT,
      key_ptr,
      data_ptr,
      A_DB_EXEC_ASYNC,
      comp);
    if (res != 0) {
        aura_iovec_destroy(key_ptr);
        aura_iovec_destroy(data_ptr);
        rv = -1;
        goto out;
    }

    rv = 0;

out:
    if (fns)
        aura_free(fns);

    return rv;
}

int aura_fn_list_delete(AURA_DBHANDLE db, struct aura_mem_ctx *mc, uint64_t job_id,
                        const char *fn_name, uint32_t fn_version, struct aura_db_completion *comp) {
    struct aura_functions *fns;
    struct aura_iovec key;
    int res, del_idx;
    int rv, error;
    size_t fns_len;

    key = a_function_list_key;
    fns = aura_fn_list_fetch(db, &error);
    if (!fns)
        return error;

    if (fns->func_cnt == 0) {
        return -1;
    }

    /* Check for function existence */
    del_idx = -1;
    for (int i = 0; i < fns->func_cnt; ++i) {
        if (strcmp(fns->funcs[i].fn_name, fn_name) == 0 && fns->funcs[0].fn_version == fn_version) {
            del_idx = i;
        }
    }

    /* No match found for fn_name and version */
    if (del_idx == -1) {
        rv = -1;
        goto out;
    }

    struct aura_iovec *key_ptr, *data_ptr;
    struct aura_functions *fns_ptr;

    key_ptr = aura_iovec_init(mc, key.len, NULL);
    if (!key_ptr) {
        rv = -1;
        goto out;
    }

    /* reduce function cnt */
    fns_len = sizeof(*fns) + (sizeof(struct aura_fn_petite) * (fns->func_cnt - 1));
    data_ptr = aura_iovec_init(mc, fns_len, NULL);
    if (!data_ptr) {
        aura_iovec_destroy(key_ptr);
        rv = -1;
        goto out;
    }

    memcpy(key_ptr->base, key.base, key.len);
    fns_ptr = (struct aura_functions *)data_ptr->base;
    fns_ptr->funcs = (struct aura_fn_petite *)(data_ptr->base + sizeof(*fns_ptr));
    /* Copy over the new function list */
    int idx = 0;
    for (int i = 0; i < fns->func_cnt; ++i) {
        if (i == del_idx)
            continue;
        memcpy(fns_ptr->funcs[idx].fn_name, fns->funcs[i].fn_name, A_FN_NAME_MAX_LEN);
        fns_ptr->funcs[idx].fn_version = fns->funcs[i].fn_version;
        fns_ptr->funcs[idx].job_id = fns->funcs[i].job_id;
        idx++;
    }
    fns_ptr->func_cnt = fns->func_cnt - 1;

    res = aura_db_record_insert(
      db,
      A_DB_NS_FN,
      A_DB_SCHEMA_FNS,
      job_id,
      0,
      A_DB_OP_INSERT,
      key_ptr,
      data_ptr,
      A_DB_EXEC_ASYNC,
      comp);
    if (res != 0) {
        aura_iovec_destroy(key_ptr);
        aura_iovec_destroy(data_ptr);
        rv = -1;
        goto out;
    }

    rv = 0;
out:
    if (fns)
        aura_free(fns);
    return rv;
}

int aura_fn_meta_parse(void *meta, struct aura_fn_meta *fn_meta) {
    const st_aura_blob_node *nodes;
    const st_aura_blob_arr_entry *arrs;
    const st_aura_blob_kv_pair *kv_pairs, *kv;
    const char *strtab;
    const int *fn_tab;
    const st_aura_blob_node *kv_val_node;
    uint32_t kv_cnt, kv_idx, arr_cnt, arr_idx;
    const char *kv_key, *kv_val;

    if (!meta)
        return -1;

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
    return -1;
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

    if (!config)
        return -1;

    nodes = aura_blob_get_nodes(config);
    kv_pairs = aura_blob_get_kvs(config);
    arrs = aura_blob_get_arrs(config);
    strtab = aura_blob_get_strtab(config);
    fn_tab = aura_blob_get_tab(config);

    memset(fn_config, 0, sizeof(*fn_config));

    const st_aura_blob_node *env_node;
    int env_cnt;

    /* Envs */
    if (fn_tab[A_IDX_FN_ENV] != 0) {
        int i;

        env_cnt = 0;
        env_node = &nodes[fn_tab[A_IDX_FN_ENV]];
        kv_cnt = env_node->map.kv_cnt;
        kv_idx = env_node->map.kv_idx;

        fn_config->envs = malloc(kv_cnt * sizeof(struct aura_iovec));
        if (!fn_config->envs)
            goto exception;

        for (i = 0; i < kv_cnt; ++i) {
            kv = &kv_pairs[kv_idx + i];
            kv_key = strtab + kv->key_offset;
            kv_val_node = &nodes[kv->node_idx];

            fn_config->envs[i].base = strdup(strtab + kv_val_node->str_offset);
            fn_config->envs[i].len = strlen(fn_config->envs[i].base);
            env_cnt++;
        }
        /* Terminate */
        fn_config->env_cnt = env_cnt;
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

    return 0;
exception:
    aura_fn_config_destroy(fn_config);
    return -1;
}

void *aura_fn_config_blob(struct aura_fn_config *config) {
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
        for (int i = 0; i < fn_config->env_cnt; ++i) {
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

void aura_fn_destroy(struct aura_fn *fn) {
    aura_fn_meta_destroy(&fn->meta);
    aura_fn_config_destroy(&fn->config);
    aura_free(fn->fn_code);
}

struct aura_fn_petite *aura_fn_petite_fetch(AURA_DBHANDLE db, struct aura_mem_ctx *mc,
                                            const char *fn_name, uint32_t fn_version, int *error) {
    struct aura_fn_petite *fn_petite;
    struct aura_functions *fns;
    struct aura_iovec key, data;

    fns = aura_fn_list_fetch(db, error);
    if (!fns) {
        return NULL;
    }

    if (fns->func_cnt == 0) {
        *error = 0;
        return NULL;
    }

    data.base = NULL;
    data.len = 0;
    /* Function version not provided */
    if (fn_version == UINT32_MAX) {
        /** Loop reverse to get the latest function version  */
        for (int i = fns->func_cnt - 1; i >= 0; --i) {
            if (strcmp(fns->funcs[i].fn_name, fn_name) == 0) {
                /* verify if job committed */
                struct aura_db_job_rec *job;
                uint8_t job_state;

                job = aura_db_job_fetch(db, fns->funcs[i].job_id, error);
                if (!job) {
                    aura_free(fns);
                    return NULL;
                }

                job_state = job->state;
                /* Record no longer needed */
                aura_free(job);
                if (job_state != A_DB_JOB_DONE) {
                    aura_free(fns);
                    return NULL;
                }

                data.len = sizeof(struct aura_fn_petite);
                data.base = aura_alloc(mc, data.len);
                memcpy(data.base, &fns->funcs[i], data.len);
                break;
            }
        }
    } else {
        /* version was provided */
        for (int i = fns->func_cnt - 1; i >= 0; --i) {
            if (strcmp(fns->funcs[i].fn_name, fn_name) == 0 && fns->funcs[i].fn_version == fn_version) {
                /* verify if job committed */
                struct aura_db_job_rec *job;
                uint8_t job_state;

                job = aura_db_job_fetch(db, fns->funcs[i].job_id, error);
                if (!job) {
                    aura_free(fns);
                    return NULL;
                }

                job_state = job->state;
                /* Record no longer needed */
                aura_free(job);
                if (job_state != A_DB_JOB_DONE) {
                    aura_free(fns);
                    return NULL;
                }

                data.len = sizeof(struct aura_fn_petite);
                data.base = aura_alloc(mc, data.len);
                memcpy(data.base, &fns->funcs[i], data.len);
                break;
            }
        }
    }

    aura_free(fns);
    return (struct aura_fn_petite *)data.base;
}

struct aura_fn_petite *aura_fn_petite_fetch_broker(struct aura_mem_ctx *mc, const char *fn_name,
                                                   uint32_t fn_version, int sock_fd) {
    struct aura_fn_petite *fn_petite;
    struct aura_db_rec *rec;
    struct aura_iovec key, data_out;
    char buf[2046];
    int res;

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf) - 1, "%s:%u", fn_name, fn_version);
    key.base = buf;
    key.len = strlen(buf);
    res = aura_db_broker_fetch(mc, A_DB_NS_FN, A_DB_SCHEMA_FN_PETITE_V1, &key, &data_out, sock_fd);
    if (res < 0) {
        return NULL;
    }

    rec = (struct aura_db_rec *)data_out.base;
    return (struct aura_fn_petite *)rec->data.base;
}

struct aura_iovec aura_fn_meta_fetch(AURA_DBHANDLE db, const char *fn_name, uint32_t fn_version) {
    struct aura_iovec key;
    struct aura_db_rec rec;
    struct aura_iovec meta;
    char buf[2046];
    int res;

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version, A_DB_SCHEMA_SUFFIX_META);
    key.base = buf;
    key.len = strlen(buf);

    res = aura_db_record_fetch(db, A_DB_NS_FN, A_DB_SCHEMA_FN_META_V1, &key, &rec);
    if (res < 0 || res == A_DB_REC_NOT_FOUND) {
        meta.base = NULL;
        meta.len = 0;
        return meta;
    }

    meta.base = rec.data.base;
    meta.len = rec.data.len;
    return meta;
}

struct aura_iovec aura_fn_config_fetch(AURA_DBHANDLE db, const char *fn_name, uint32_t fn_version) {
    struct aura_iovec key;
    struct aura_db_rec rec;
    struct aura_iovec config;
    char buf[2046];
    int res;

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version, A_DB_SCHEMA_SUFFIX_CONFIG);
    key.base = buf;
    key.len = strlen(buf);

    res = aura_db_record_fetch(db, A_DB_NS_FN, A_DB_SCHEMA_FN_CONFIG_V1, &key, &rec);
    if (res < 0 || res == A_DB_REC_NOT_FOUND) {
        config.base = NULL;
        config.len = 0;
        return config;
    }

    config.base = rec.data.base;
    config.len = rec.data.len;
    return config;
}

struct aura_iovec aura_fn_code_fetch(AURA_DBHANDLE db, const char *fn_name, uint32_t fn_version) {
    struct aura_iovec key;
    struct aura_db_rec rec;
    struct aura_iovec code;
    char buf[2046];
    int res;

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version, A_DB_SCHEMA_SUFFIX_CODE);
    key.base = buf;
    key.len = strlen(buf);

    res = aura_db_record_fetch(db, A_DB_NS_FN, A_DB_SCHEMA_FN_CODE_V1, &key, &rec);
    if (res < 0 || res == A_DB_REC_NOT_FOUND) {
        code.base = NULL;
        code.len = 0;
        return code;
    }

    code.base = rec.data.base;
    code.len = rec.data.len;
    return code;
}

struct aura_iovec aura_fn_state_fetch(AURA_DBHANDLE db, const char *fn_name, uint32_t fn_version) {
    struct aura_iovec key;
    struct aura_db_rec rec;
    struct aura_iovec state;
    char buf[2046];
    int res;

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version, A_DB_SCHEMA_SUFFIX_STATE);
    key.base = buf;
    key.len = strlen(buf);

    res = aura_db_record_fetch(db, A_DB_NS_FN, A_DB_SCHEMA_FN_STATE_V1, &key, &rec);
    if (res < 0 || res == A_DB_REC_NOT_FOUND) {
        state.base = NULL;
        state.len = 0;
        return state;
    }

    state.base = rec.data.base;
    state.len = rec.data.len;
    return state;
}

struct aura_fn *aura_fn_load(AURA_DBHANDLE db, struct aura_mem_ctx *mc,
                             const char *fn_name, uint32_t fn_version) {
    struct aura_fn *fn;
    struct aura_iovec key;
    struct aura_db_rec rec;
    struct aura_fn_petite *fn_petite;
    char buf[2000];
    int res, error;

    fn = aura_alloc(mc, sizeof(*fn));
    if (!fn)
        return NULL;
    /* Check if fn available */
    /* @todo, check and respect function state and policy */
    fn_petite = aura_fn_petite_fetch(db, mc, fn_name, fn_version, &error);
    if (!fn_petite)
        return NULL;

    /* Meta */
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version, A_DB_SCHEMA_SUFFIX_META);
    key.base = buf;
    key.len = strlen(buf);
    res = aura_db_record_fetch(db, A_DB_NS_FN, A_DB_SCHEMA_FN_META_V1, &key, &rec);
    if (res < 0 || res == A_DB_REC_NOT_FOUND) {
        return NULL;
    }

    if (aura_fn_meta_parse(rec.data.base, &fn->meta) < 0) {
        aura_free(rec.data.base);
        return NULL;
    }
    aura_free(rec.data.base);

    /* Config */
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version, A_DB_SCHEMA_SUFFIX_CONFIG);
    key.base = buf;
    key.len = strlen(buf);
    res = aura_db_record_fetch(db, A_DB_NS_FN, A_DB_SCHEMA_FN_CONFIG_V1, &key, &rec);
    if (res < 0 || res == A_DB_REC_NOT_FOUND) {
        return NULL;
    }

    if (aura_fn_config_parse(rec.data.base, &fn->config) < 0) {
        aura_free(rec.data.base);
        return NULL;
    }

    aura_free(rec.data.base);

    /* Stats */
    struct aura_fn_stat *s = aura_fn_stat_fetch(db, fn_name, fn_version);

    memcpy(&fn->stats, s, sizeof(fn->stats));
    aura_free(s);

    /* State */
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version, A_DB_SCHEMA_SUFFIX_STATE);
    key.base = buf;
    key.len = strlen(buf);
    res = aura_db_record_fetch(db, A_DB_NS_FN, A_DB_SCHEMA_FN_STATE_V1, &key, &rec);
    if (res < 0 || res == A_DB_REC_NOT_FOUND) {
        return NULL;
    }

    memcpy(&fn->state, rec.data.base, sizeof(fn->state));
    aura_free(rec.data.base);

    /* Code */
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version, A_DB_SCHEMA_SUFFIX_CODE);
    key.base = buf;
    key.len = strlen(buf);
    res = aura_db_record_fetch(db, A_DB_NS_FN, A_DB_SCHEMA_FN_CODE_V1, &key, &rec);
    if (res < 0 || res == A_DB_REC_NOT_FOUND) {
        return NULL;
    }
    /* We transfer memory ownership to fn */
    fn->fn_code = rec.data.base;
    fn->fn_code_len = rec.data.len;
    fn->backend = 1;

    return fn;
}

struct aura_fn *aura_fn_load_broker(struct aura_mem_ctx *mc, const char *fn_name,
                                    uint32_t fn_version, int sock_fd) {
    struct aura_fn *fn;
    struct aura_iovec key, data_out;
    char buf[2000];
    int res, error;
    app_debug(true, 0, "aura_fn_load_broker <<<<");

    fn = aura_alloc(mc, sizeof(*fn));
    if (!fn)
        return NULL;
    /* Check if fn available */
    /* @todo, check and respect function state and policy */

    /* Meta */
    memset(buf, 0, sizeof(buf));
    memset(fn, 0, sizeof(*fn));
    snprintf(buf, sizeof(buf), "%s:%u", fn_name, fn_version);
    key.base = buf;
    key.len = strlen(buf);
    res = aura_db_broker_fetch(mc, A_DB_NS_FN, A_DB_SCHEMA_FN_META_V1, &key, &data_out, sock_fd);
    if (res < 0) {
        return NULL;
    }

    if (aura_fn_meta_parse(data_out.base, &fn->meta) < 0) {
        return NULL;
    }
    aura_free(data_out.base);

    /* Config */
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "%s:%u", fn_name, fn_version);
    key.base = buf;
    key.len = strlen(buf);
    res = aura_db_broker_fetch(mc, A_DB_NS_FN, A_DB_SCHEMA_FN_CONFIG_V1, &key, &data_out, sock_fd);
    if (res < 0) {
        return NULL;
    }

    if (aura_fn_config_parse(data_out.base, &fn->config) < 0) {
        return NULL;
    }
    aura_free(data_out.base);

    /* Stats */
    struct aura_fn_stat *s = aura_fn_stat_fetch_broker(mc, fn_name, fn_version, sock_fd);
    if (!s)
        return NULL;

    memcpy(&fn->stats, s, sizeof(fn->stats));
    aura_free(s);

    /* State */
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "%s:%u", fn_name, fn_version);
    key.base = buf;
    key.len = strlen(buf);
    res = aura_db_broker_fetch(mc, A_DB_NS_FN, A_DB_SCHEMA_FN_STATE_V1, &key, &data_out, sock_fd);
    if (res < 0) {
        return NULL;
    }

    memcpy(&fn->state, data_out.base, sizeof(fn->state));
    aura_free(data_out.base);

    /* Code */
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "%s:%u", fn_name, fn_version);
    key.base = buf;
    key.len = strlen(buf);
    res = aura_db_broker_fetch(mc, A_DB_NS_FN, A_DB_SCHEMA_FN_CODE_V1, &key, &data_out, sock_fd);
    if (res < 0) {
        return NULL;
    }

    /* transfer ownership of function */
    fn->fn_code = data_out.base;
    fn->fn_code_len = data_out.len;
    fn->backend = 1; /* JS backend */

    return fn;
}

struct aura_fn_stat *aura_fn_stat_fetch(AURA_DBHANDLE db, const char *fn_name, uint32_t fn_version) {
    struct aura_fn_stat *fn_stat;
    struct aura_iovec key;
    struct aura_db_rec rec;
    char buf[2000];
    int res;

    snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version, A_DB_SCHEMA_SUFFIX_STAT);
    key.base = buf;
    key.len = strlen(buf);

    res = aura_db_record_fetch(db, A_DB_NS_FN, A_DB_SCHEMA_FN_STAT_DELTA, &key, &rec);
    if (res != 0)
        return NULL;

    return (struct aura_fn_stat *)rec.data.base;
}

struct aura_fn_stat *aura_fn_stat_fetch_broker(struct aura_mem_ctx *mc, const char *fn_name,
                                               uint32_t fn_version, int dmn_fd) {
    struct aura_fn_stat *fn_stat;
    struct aura_iovec key, data_out;
    char buf[2000];
    int res;

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "%s:%u", fn_name, fn_version);
    key.base = buf;
    key.len = strlen(buf);

    res = aura_db_broker_fetch(mc, A_DB_NS_FN, A_DB_SCHEMA_FN_STAT_DELTA, &key, &data_out, dmn_fd);
    if (res < 0)
        return NULL;

    fn_stat = (struct aura_fn_stat *)data_out.base;
    return fn_stat;
}

int aura_fn_stat_compare(struct aura_heap_ent *s1, struct aura_heap_ent *s2) {
    struct aura_fn_stat_wrapper *_s1;
    struct aura_fn_stat_wrapper *_s2;

    _s1 = aura_container_of(s1, struct aura_fn_stat_wrapper, hp_ent);
    _s2 = aura_container_of(s2, struct aura_fn_stat_wrapper, hp_ent);

    return _s1->fn_stat->invocations - _s2->fn_stat->invocations;
}

void aura_fn_meta_dump(struct aura_fn_meta *fn_conf) {
    /**/
}

void aura_fn_config_dump(struct aura_fn_config *fn_conf) {
    app_debug(true, 0, "Aura FN CONFIG");
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

void aura_fn_stat_dump(struct aura_fn_stat *stats) {
    app_debug(true, 0, "Aura FN Stats");
    app_debug(true, 0, "    Total invocations: %lu", stats->invocations);
    app_debug(true, 0, "    Average exec ns: %lu", stats->exec_ns);
    app_debug(true, 0, "    Total cold starts: %lu", stats->cold_starts);
    app_debug(true, 0, "    Total failures: %lu", stats->failures);
    app_debug(true, 0, "    Latency: %lu", stats->latency_ns);
    app_debug(true, 0, "    Last execution: %lu", stats->last_execution);
}
