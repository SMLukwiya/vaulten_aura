#include "blobber/lib.h"
#include "bug_lib.h"
#include "db/broker.h"
#include "lib.h"
#include "string_lib.h"

int _fn_conf_tab[] = {
  [A_IDX_FN_NONE] = 0,
  [A_IDX_FN_FUNCTION] = 0,
  [A_IDX_FN_NAME] = 0,
  [A_IDX_FN_DESCRIPTION] = 0,
  [A_IDX_FN_ID] = 0,
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

struct aura_fn_list *aura_fn_list_fetch(struct aura_mem_ctx *mc, AURA_DBHANDLE db,
                                        int dmn_sock_fd, int *error) {
    struct aura_fn_list *fn_list;
    struct aura_iovec key, data_out;
    struct aura_db_rec rec;
    int rv;

    key = a_function_list_key;
    /* brokered */
    if (dmn_sock_fd != -1) {
        rv = aura_db_brokered_fetch(mc, A_NS_FN, A_FN_LIST_SCHEMA_ID, &key, &data_out, dmn_sock_fd);
        if (rv < 0) {
            *error = rv;
            return NULL;
        }

        fn_list = (struct aura_fn_list *)data_out.base;
    } else {
        A_BUG_ON_2(!db, true);

        rv = aura_db_fetch(db, A_NS_FN, A_FN_LIST_SCHEMA_ID, &key, &rec);
        if (rv < 0 || rv == A_DB_REC_NOT_FOUND) {
            *error = rv;
            return NULL;
        }

        fn_list = (struct aura_fn_list *)rec.data.base;
    }

    if (!fn_list)
        return NULL;
    /**
     * function tags stored in continuous fashion
     * after aura_fn_list structure.
     */
    fn_list->func_tags = (struct aura_fn_tag *)((char *)fn_list + sizeof(*fn_list));

    return fn_list;
}

static int a_fn_triggers_parse(void *meta, struct aura_fn_triggers *fn_triggers) {
    const st_aura_blob_node *nodes;
    const st_aura_blob_kv_pair *kv_pairs, *kv;
    const char *strtab;
    const int *fn_tab;
    const st_aura_blob_node *kv_val_node;
    uint32_t kv_cnt, kv_idx, arr_cnt, arr_idx;
    const char *kv_key, *kv_val;

    nodes = aura_blob_get_nodes(meta);
    kv_pairs = aura_blob_get_kvs(meta);
    strtab = aura_blob_get_strtab(meta);
    fn_tab = aura_blob_get_tab(meta);

    const st_aura_blob_node *trigger_node;

    fn_triggers->cnt = 0;
    if (fn_tab[A_IDX_FN_TRIGGERS] != 0) {
        struct aura_fn_http_trigger *http_trigger = &fn_triggers->entries[fn_triggers->cnt].http;
        /* http */
        if (fn_tab[A_IDX_FN_HTTP_TRIGGER] != 0) {
            trigger_node = &nodes[fn_tab[A_IDX_FN_HTTP_TRIGGER]];
            kv_idx = trigger_node->map.kv_idx;
            kv_cnt = trigger_node->map.kv_cnt;

            for (int i = 0; i < kv_cnt; ++i) {
                kv = &kv_pairs[kv_idx + i];
                kv_val_node = &nodes[kv->node_idx];
                kv_key = strtab + kv->key_offset;

                if (strcmp(kv_key, "path") == 0) {
                    kv_val = strtab + kv_val_node->str.offset;
                    http_trigger->path.base = strdup(kv_val);
                    http_trigger->path.len = strlen(kv_val);
                }

                if (strcmp(kv_key, "method") == 0) {
                    kv_val = strtab + kv_val_node->str.offset;
                    if (aura_scan_str(kv_val, "%d" SCNd32, &http_trigger->method) < 0)
                        return -1;
                }

                if (strcmp(kv_key, "auth") == 0) {
                    /**/
                }
            }
            fn_triggers->entries[fn_triggers->cnt].trigger = A_FN_TRIGGER_HTTP;
            fn_triggers->cnt++;
        }

        /* Cron trigger */
        if (fn_tab[A_IDX_FN_CRON_TRIGGER] != 0) {
            struct aura_fn_cron_trigger *cron_trigger = &fn_triggers->entries[fn_triggers->cnt].cron;
            trigger_node = &nodes[fn_tab[A_IDX_FN_CRON_TRIGGER]];
            kv_idx = trigger_node->map.kv_idx;
            kv_cnt = trigger_node->map.kv_cnt;

            memset(cron_trigger, 0, sizeof(*cron_trigger));
            for (int i = 0; i < kv_cnt; ++i) {
                kv = &kv_pairs[kv_idx + i];
                kv_val_node = &nodes[kv->node_idx];
                kv_key = strtab + kv->key_offset;

                if (strcmp(kv_key, "schedule") == 0) {
                    kv_val = strtab + kv_val_node->str.offset;
                    snprintf(cron_trigger->cron_schedule, 13, "%s", kv_val);
                }

                if (strcmp(kv_key, "jitter_seconds") == 0) {
                    kv_val = strtab + kv_val_node->str.offset;
                    if (aura_scan_str(kv_val, "%d" SCNu64, &cron_trigger->jitter_seconds) < 0)
                        return -1;
                }

                if (strcmp(kv_key, "misfire_policy") == 0) {
                    kv_val = strtab + kv_val_node->str.offset;
                    if (aura_scan_str(kv_val, "%u" SCNu8, &cron_trigger->misfire_policy) < 0)
                        return -1;
                }

                if (fn_tab[A_IDX_FN_CRON_RETRIES] != 0) {
                    const st_aura_blob_node *cron_trigger_retry_node;
                    cron_trigger_retry_node = &nodes[fn_tab[A_IDX_FN_CRON_RETRIES]];
                }
            }
            fn_triggers->entries[fn_triggers->cnt].trigger = A_FN_TRIGGER_CRON;
            fn_triggers->cnt++;
        }

        /* Queue trigger */
        if (fn_tab[A_IDX_FN_QUEUE_TRIGGER] != 0) {
            trigger_node = &nodes[fn_tab[A_IDX_FN_QUEUE_TRIGGER]];
            kv_idx = trigger_node->map.kv_idx;
            kv_cnt = trigger_node->map.kv_cnt;

            for (int i = 0; i < kv_cnt; ++i) {
                kv = &kv_pairs[kv_idx + i];
                kv_val_node = &nodes[kv->node_idx];
                kv_key = strtab + kv->key_offset;

                if (strcmp(kv_key, "topic") == 0) {
                    kv_val = strtab + kv_val_node->str.offset;
                }
            }
        }
    }

    return 0;
}

/**
 * Adds a new function to the app function list
 * If function list record does not exist, create
 * one on the fly.
 */
int aura_fn_list_add_fn(AURA_DBHANDLE db, struct aura_mem_ctx *mc, struct aura_fn_meta *fn_meta) {
    struct aura_fn_list *fn_list, *fns_ptr;
    struct aura_iovec fn_list_key, fn_list_data;
    struct aura_fn_tag *new_fn;
    size_t fns_len;
    int error;

    fn_list_key.base = A_FN_LIST_KEY;
    fn_list_key.len = sizeof(A_FN_LIST_KEY) - 1;

    fn_list = aura_fn_list_fetch(mc, db, -1, &error);
    if (!fn_list) {
        if (error < 0)
            return error;

        /**
         * Create a new function list record with
         * the current function as the only function
         * in its list.
         */
        fns_len = sizeof(struct aura_fn_list) + sizeof(struct aura_fn_tag);
        char buf[fns_len];

        memset(buf, 0, fns_len);
        fn_list_data.base = buf;
        fn_list_data.len = fns_len;
        fn_list = (struct aura_fn_list *)fn_list_data.base;
        fn_list->func_cnt = 1;
        fn_list->func_tags = (struct aura_fn_tag *)(fn_list_data.base + sizeof(*fn_list));

        new_fn = &fn_list->func_tags[0];
        memcpy(new_fn->fn_name, fn_meta->name, strlen(fn_meta->name));
        if (fn_meta->version)
            memcpy(new_fn->fn_version, fn_meta->version, strlen(fn_meta->version));
        new_fn->fn_id = fn_meta->fn_id;
        new_fn->timestamp_ms = fn_meta->fn_id;
        new_fn->http = fn_meta->http_trigger.path.base ? true : false;

        if (aura_db_insert(
              db,
              A_NS_FN,
              A_FN_LIST_SCHEMA_ID,
              0,
              A_DB_INSERT_OP,
              &fn_list_key,
              &fn_list_data) != 0)
            return -1;

        return 0;
    }

    /**
     * Update existing function list record
     * Increment function count
     * Add the newest functions at the beginning
     * of the updated list.
     */
    fns_len = sizeof(*fn_list) + (sizeof(struct aura_fn_tag) * (fn_list->func_cnt + 1));
    fn_list_data.len = fns_len;
    fn_list_data.base = aura_alloc(mc, fns_len);
    if (!fn_list_data.base) {
        aura_free((void *)fn_list);
        return -1;
    }

    /**
     * copy over the current list leaving the
     * first position for the new fn tag entry.
     */
    fns_ptr = (struct aura_fn_list *)fn_list_data.base;
    fns_ptr->func_tags = (struct aura_fn_tag *)(fn_list_data.base + sizeof(*fns_ptr));

    *fns_ptr = *fn_list;
    memcpy((void *)(fns_ptr->func_tags + 1), (void *)(fn_list->func_tags), sizeof(struct aura_fn_tag) * fn_list->func_cnt);

    /* Copy over new function tag to created slot on fn list */
    memset(fns_ptr->func_tags, 0, sizeof(struct aura_fn_tag));
    memcpy(fns_ptr->func_tags[0].fn_name, fn_meta->name, strlen(fn_meta->name));
    memcpy(fns_ptr->func_tags[0].fn_version, fn_meta->version, strlen(fn_meta->version));
    new_fn->fn_id = fn_meta->fn_id;
    new_fn->timestamp_ms = fn_meta->fn_id;

    fns_ptr->func_cnt++;

    if (aura_db_insert(
          db,
          A_NS_FN,
          A_FN_LIST_SCHEMA_ID,
          0,
          A_DB_INSERT_OP,
          &fn_list_key,
          &fn_list_data) < 0) {
        aura_free((void *)fn_list);
        return -1;
    }

    aura_free(fn_list_data.base);
    aura_free((void *)fn_list);
    return 0;
}

int aura_fn_list_delete(AURA_DBHANDLE db, struct aura_mem_ctx *mc,
                        char *name, char *version) {
    struct aura_fn_list *fn_list;
    struct aura_fn_tag *tag_arr;
    struct aura_iovec key, data;
    struct aura_fn_tag *del_tag;
    int res, del_idx;
    int rv, error;
    size_t fns_len;

    key = a_function_list_key;
    fn_list = aura_fn_list_fetch(mc, db, -1, &error);
    if (!fn_list)
        return error;

    if (fn_list->func_cnt == 0) {
        return -1;
    }

    /* Check for function existence */
    fns_len = sizeof(*fn_list) + (sizeof(struct aura_fn_tag) * (fn_list->func_cnt - 1));
    for (int i = 0; i < fn_list->func_cnt; ++i) {
        if (memcmp(fn_list->func_tags[i].fn_name, name, A_FN_NAME_MAX_LEN) == 0 &&
            memcmp(fn_list->func_tags[i].fn_version, version, A_FN_VERSION_MAX_LEN) == 0) {
            /* Delete index of matching function */
            tag_arr = (struct aura_fn_tag *)((char *)(fn_list) + sizeof(*fn_list));
            /* Tag to delete */
            del_tag = &fn_list->func_tags[i];

            /* Update fn count */
            --(fn_list->func_cnt);

            /**
             * If fn tag is not at the last index.
             * Reuse same fn_list record
             * copy over the deleted fn tag
             * moving everything to the right of
             * the deleted fn
             */
            if (i < fn_list->func_cnt)
                memmove(&tag_arr[i], &tag_arr[i + 1], sizeof(*tag_arr) * (fn_list->func_cnt - i));
            break;
        }
    }

    data.base = (char *)fn_list;
    data.len = fns_len;

    rv = 0;
    if (aura_db_insert(
          db,
          A_NS_FN,
          A_FN_LIST_SCHEMA_ID,
          0,
          A_DB_INSERT_OP,
          &key,
          &data) != 0) {
        rv = -1;
    }

    aura_free((void *)fn_list);
    return rv;
}

int aura_fn_meta_parse(void *meta, struct aura_fn_meta *fn_meta) {
    const st_aura_blob_node *nodes, *node;
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

    memset(fn_meta, 0, sizeof(*fn_meta));
    /* Fn name */
    if (fn_tab[A_IDX_FN_NAME] != 0) {
        node = &nodes[fn_tab[A_IDX_FN_NAME]];
        fn_meta->name = strdup(strtab + node->str.offset);
    }

    /* Description */
    if (fn_tab[A_IDX_FN_DESCRIPTION] != 0) {
        node = &nodes[fn_tab[A_IDX_FN_DESCRIPTION]];
        fn_meta->description = strdup(strtab + node->str.offset);
    }

    /* Version */
    if (fn_tab[A_IDX_FN_VERSION] != 0) {
        node = &nodes[fn_tab[A_IDX_FN_VERSION]];
        fn_meta->version = strdup(strtab + node->str.offset);
    }

    /* FN ID */
    if (fn_tab[A_IDX_FN_ID] != 0) {
        const char *fn_id;
        node = &nodes[fn_tab[A_IDX_FN_ID]];
        fn_id = strtab + node->str.offset;
        if (aura_scan_str(fn_id, "%lu" SCNu64, &fn_meta->fn_id) < 0)
            goto exception;
    }

    /* Entry */
    if (fn_tab[A_IDX_FN_ENTRY_POINT] != 0) {
        node = &nodes[fn_tab[A_IDX_FN_ENTRY_POINT]];
        fn_meta->entry_point = strdup(strtab + node->str.offset);
    }

    /* Host */
    if (fn_tab[A_IDX_FN_HOST] != 0) {
        node = &nodes[fn_tab[A_IDX_FN_HOST]];
        fn_meta->host = strdup(strtab + node->str.offset);
    }

    /* FN triggers */
    const st_aura_blob_node *fn_triggers_node, *http_trigger_node, *cron_trigger_node, *queue_trigger_node;
    const st_aura_blob_node *cron_trigger_retry_node;

    if (a_fn_triggers_parse(meta, &fn_meta->triggers) < 0)
        goto exception;

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
                kv_val = strtab + kv_val_node->str.offset;
                if (aura_scan_str(kv_val, "%u" SCNu32, &fn_meta->fn_resources.mem_limit_mb_soft) < 0)
                    goto exception;
            }

            if (strcmp(kv_key, "hard") == 0) {
                kv_val = strtab + kv_val_node->str.offset;
                if (aura_scan_str(kv_val, "%u" SCNu32, &fn_meta->fn_resources.mem_limit_mb_hard) < 0)
                    goto exception;
            }

            if (strcmp(kv_key, "oom_policy") == 0) {
                kv_val = strtab + kv_val_node->str.offset;
                if (aura_scan_str(kv_val, "%u" SCNu8, &fn_meta->fn_resources.oom_policy) < 0)
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

            fn_config->envs[i].base = strdup(strtab + kv_val_node->str.offset);
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
            instances = strtab + min_instance_node->str.offset;
            if (aura_scan_str(instances, "%d" SCNu32, &fn_config->fn_concurrency.min_instances) < 0) {
                goto exception;
            }
        }

        if (fn_tab[A_IDX_FN_MAX_INSTANCES] != 0) {
            max_instance_node = &nodes[fn_tab[A_IDX_FN_MAX_INSTANCES]];
            instances = strtab + max_instance_node->str.offset;
            if (aura_scan_str(instances, "%d" SCNu32, &fn_config->fn_concurrency.max_instances) < 0)
                goto exception;
        }

        if (fn_tab[A_IDX_FN_PREWARM] != 0) {
            max_instance_node = &nodes[fn_tab[A_IDX_FN_PREWARM]];
            instances = strtab + max_instance_node->str.offset;
            if (aura_scan_str(instances, "%d" SCNu32, &fn_config->fn_concurrency.pre_warm_on_deploy) < 0)
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
        free((void *)fn_meta->name);
    if (fn_meta->description)
        free((void *)fn_meta->description);

    if (fn_meta->version)
        free((void *)fn_meta->version);

    if (fn_meta->prev_version)
        free((void *)fn_meta->prev_version);

    if (fn_meta->host)
        free((void *)fn_meta->host);
    if (fn_meta->entry_point)
        free((void *)fn_meta->entry_point);

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

struct aura_fn_tag *aura_fn_tag_fetch(AURA_DBHANDLE db, struct aura_mem_ctx *mc, const char *name,
                                      const char *version, int *error) {
    struct aura_fn_list *fn_list;
    struct aura_iovec data;
    bool fn_tag_found;

    fn_list = aura_fn_list_fetch(mc, db, -1, error);
    if (!fn_list) {
        return NULL;
    }

    if (fn_list->func_cnt == 0) {
        *error = 0;
        return NULL;
    }

    data.base = NULL;
    data.len = 0;

    for (int i = fn_list->func_cnt - 1; i >= 0; --i) {
        /**
         * Check if fn version was provided
         * Function version is always passed as an array of
         * chars, set to 0 if empty.
         */
        if (version[0] != '\0')
            fn_tag_found = memcmp(fn_list->func_tags[i].fn_name, name, A_FN_NAME_MAX_LEN) == 0 &&
                           memcmp(fn_list->func_tags[i].fn_version, version, A_FN_VERSION_MAX_LEN) == 0;
        else
            fn_tag_found = memcmp(fn_list->func_tags[i].fn_name, name, A_FN_NAME_MAX_LEN) == 0;

        if (fn_tag_found) {
            data.len = sizeof(struct aura_fn_tag);
            data.base = aura_alloc(mc, data.len);
            memcpy(data.base, &fn_list->func_tags[i], data.len);
            break;
        }
    }

    aura_free(fn_list);
    return (struct aura_fn_tag *)data.base;
}

struct aura_iovec aura_fn_state_fetch(struct aura_mem_ctx *mc, char *name, char *version,
                                      AURA_DBHANDLE db, int dmn_sock_fd) {
    struct aura_iovec key, data_out;
    struct aura_db_rec rec;
    struct aura_iovec fn_state;
    char buf[2046];
    int rv;

    memset(buf, 0, sizeof(buf));
    fn_state.base = NULL;
    fn_state.len = 0;

    /* brokered */
    if (dmn_sock_fd != -1) {
        snprintf(buf, sizeof(buf), "%s:%s", name, version);
        key.base = buf;
        key.len = strlen(buf);
        if (aura_db_brokered_fetch(mc, A_NS_FN, A_FN_STATE_SCHEMA_ID, &key, &data_out, dmn_sock_fd) < 0)
            return fn_state;

        fn_state.base = data_out.base;
        fn_state.len = data_out.len;
    } else {
        A_BUG_ON_2(!db, true);

        snprintf(buf, sizeof(buf), "%s:%s:%s:%s", A_DB_FN_KEY_PREFIX, name, version, A_DB_FN_STATE_SUFFIX);
        key.base = buf;
        key.len = strlen(buf);

        rv = aura_db_fetch(db, A_NS_FN, A_FN_STATE_SCHEMA_ID, &key, &rec);
        if (rv < 0 || rv == A_DB_REC_NOT_FOUND) {
            return fn_state;
        }

        fn_state.base = rec.data.base;
        fn_state.len = rec.data.len;
    }

    return fn_state;
}

int aura_fn_state_load(struct aura_fn *fn, struct aura_mem_ctx *mc, char *name,
                       char *version, AURA_DBHANDLE db, int dmn_sock_fd) {
    struct aura_iovec fn_state = aura_fn_state_fetch(mc, name, version, db, dmn_sock_fd);

    /* This always exists as it's created whem the function is deployed */
    if (!fn_state.base)
        return -1;

    memcpy(&fn->state, fn_state.base, sizeof(fn->state));
    aura_free((void *)fn_state.base);
    return 0;
}

int aura_fn_queue_init(struct aura_fn_queue *fn_q, struct aura_worker_pool *glob_pool) {
    memset(fn_q, 0, sizeof(*fn_q));

    if (pthread_mutex_init(&fn_q->lock, NULL) != 0)
        return -1;

    aura_list_head_init(&fn_q->fn_node);
    aura_list_head_init(&fn_q->task_list);
    aura_list_head_init(&fn_q->exec_slots);
    fn_q->fn = NULL;
    fn_q->paused = false;
    fn_q->glob_pool = glob_pool;

    return 0;
}

void aura_fn_queue_destroy(struct aura_fn_queue *fn_q) {
    aura_list_delete(&fn_q->fn_node);
    pthread_mutex_destroy(&fn_q->lock);
}

int aura_fn_registry_init(struct aura_fn_registry *r, struct aura_mem_ctx *mc, uint32_t max_size) {
    memset(r, 0, sizeof(*r));

    if (aura_rh_map_init(&r->hashmap, mc, A_FN_MAX_REGISTRY_CNT, A_RH_KEY_U64, false) < 0)
        return -1;
}

int aura_fn_cache_init(struct aura_lru_cache *cache, struct aura_mem_ctx *mc) {
    return aura_lru_cache_init(
      cache,
      mc,
      "function cache",
      A_FN_SLAB_CACHE_ID,
      A_FN_MAX_REGISTRY_CNT,
      sizeof(struct aura_fn),
      offsetof(struct aura_fn, lc_entry));
}

struct aura_fn_registry_ent *aura_fn_load_fn_registry_entry(struct aura_fn_registry *r,
                                                            struct aura_fn_tag *fn_tag) {
    if (r->cnt >= A_FN_MAX_REGISTRY_CNT)
        return NULL;

    struct aura_fn_registry_ent *e = &r->entries[r->cnt];
    struct aura_rh_map_key key;

    e->fn = NULL;
    e->load_state = A_FN_UNLOADED;
    e->fn_tag = *fn_tag;

    if (aura_fn_queue_init(&e->fn_queue, NULL) < 0)
        return NULL;

    aura_rh_map_key_init(&key, fn_tag->fn_id, sizeof(uint64_t), A_RH_KEY_U64);

    if (aura_rh_map_put(&r->hashmap, &key, (void *)e) < 0) {
        aura_fn_queue_destroy(&e->fn_queue);
        return NULL;
    }
    r->cnt++;

    return e;
}

struct aura_iovec aura_fn_meta_fetch(struct aura_mem_ctx *mc, char *name,
                                     char *version, AURA_DBHANDLE db, int sock_fd) {
    struct aura_iovec key, data_out;
    struct aura_db_rec rec;
    char buf[2046];
    struct aura_iovec meta;
    int rv;

    memset(buf, 0, sizeof(buf));
    meta.base = NULL;
    meta.len = 0;

    /* Brokered call */
    if (sock_fd != -1) {
        snprintf(buf, sizeof(buf), "%s:%s", name, version);
        key.base = buf;
        key.len = strlen(buf);

        if (aura_db_brokered_fetch(mc, A_NS_FN, A_FN_META_SCHEMA_ID, &key, &data_out, sock_fd) < 0)
            return meta;

        meta.base = data_out.base;
        meta.len = data_out.len;

    } else {
        /* Direct call */
        A_BUG_ON_2(!db, true);
        snprintf(buf, sizeof(buf), "%s:%s:%s:%s", A_DB_FN_KEY_PREFIX, name, version, A_DB_FN_META_SUFFIX);
        key.base = buf;
        key.len = strlen(buf);

        rv = aura_db_fetch(db, A_NS_FN, A_FN_META_SCHEMA_ID, &key, &rec);
        if (rv < 0 || rv == A_DB_REC_NOT_FOUND) {
            return meta;
        }

        meta.base = rec.data.base;
        meta.len = rec.data.len;
    }

    return meta;
}

int aura_fn_meta_load(struct aura_fn *fn, struct aura_mem_ctx *mc, char *name,
                      char *version, AURA_DBHANDLE db, int sock_fd) {
    struct aura_iovec meta = aura_fn_meta_fetch(mc, name, version, db, sock_fd);
    int rv;

    if (!meta.base)
        return -1;

    rv = aura_fn_meta_parse((void *)meta.base, &fn->meta);
    aura_free((void *)meta.base);
    return rv;
}

struct aura_iovec aura_fn_config_fetch(struct aura_mem_ctx *mc, char *name,
                                       char *version, AURA_DBHANDLE db, int sock_fd) {
    char buf[2046];
    struct aura_iovec key, data_out;
    struct aura_db_rec rec;
    struct aura_iovec config;
    int rv;

    memset(buf, 0, sizeof(buf));
    config.base = NULL;
    config.len = 0;

    /* Brokered */
    if (sock_fd != -1) {
        snprintf(buf, sizeof(buf), "%s:%s", name, version);
        key.base = buf;
        key.len = strlen(buf);
        if (aura_db_brokered_fetch(mc, A_NS_FN, A_FN_CONF_SCHEMA_ID, &key, &data_out, sock_fd) < 0)
            return config;

        config.base = data_out.base;
        config.len = data_out.len;

    } else {
        /* Direct call */
        A_BUG_ON_2(!db, true);
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%s:%s:%s:%s", A_DB_FN_KEY_PREFIX, name, version, A_DB_FN_CONF_SUFFIX);
        key.base = buf;
        key.len = strlen(buf);
        rv = aura_db_fetch(db, A_NS_FN, A_FN_CONF_SCHEMA_ID, &key, &rec);
        if (rv < 0 || rv == A_DB_REC_NOT_FOUND) {
            return config;
        }

        config.base = rec.data.base;
        config.len = rec.data.len;
    }

    return config;
}

int aura_fn_config_load(struct aura_fn *fn, struct aura_mem_ctx *mc, char *name,
                        char *version, AURA_DBHANDLE db, int sock_fd) {
    struct aura_iovec config = aura_fn_config_fetch(mc, name, version, db, sock_fd);
    int rv;

    if (!config.base)
        return -1;

    rv = aura_fn_config_parse((void *)config.base, &fn->config);
    aura_free((void *)config.base);

    return rv;
}

struct aura_fn_stat *aura_fn_stat_fetch(struct aura_mem_ctx *mc, char *name, char *version,
                                        AURA_DBHANDLE db, int dmn_sock_fd) {
    struct aura_fn_stat *fn_stat;
    struct aura_iovec key, data_out;
    struct aura_db_rec rec;
    char buf[2046];
    int rv;

    memset(buf, 0, sizeof(buf));
    /* Brokered */
    if (dmn_sock_fd != -1) {
        snprintf(buf, sizeof(buf), "%s:%s", name, version);
        key.base = buf;
        key.len = strlen(buf);

        if (aura_db_brokered_fetch(mc, A_NS_FN, A_FN_STAT_DELTA_SCHEMA_ID, &key, &data_out, dmn_sock_fd) < 0)
            return NULL;

        fn_stat = (struct aura_fn_stat *)data_out.base;
    } else {
        A_BUG_ON_2(!db, true);
        snprintf(buf, sizeof(buf), "%s:%s:%s:%s", A_DB_FN_KEY_PREFIX, name, version, A_DB_FN_STAT_SUFFIX);
        key.base = buf;
        key.len = strlen(buf);

        rv = aura_db_fetch(db, A_NS_FN, A_FN_STAT_DELTA_SCHEMA_ID, &key, &rec);
        if (rv != 0)
            return NULL;

        fn_stat = (struct aura_fn_stat *)rec.data.base;
    }

    return fn_stat;
}

int aura_fn_stat_load(struct aura_fn *fn, struct aura_mem_ctx *mc, char *name,
                      char *version, AURA_DBHANDLE db, int dmn_sock_fd) {
    struct aura_fn_stat *stats = aura_fn_stat_fetch(mc, name, version, db, dmn_sock_fd);

    if (!stats)
        return -1;

    memcpy(&fn->stats, stats, sizeof(*stats));
    aura_free((void *)stats);
    return 0;
}

struct aura_iovec aura_fn_code_fetch(struct aura_mem_ctx *mc, char *name, char *version,
                                     AURA_DBHANDLE db, int dmn_sock_fd) {
    struct aura_iovec key, data_out;
    struct aura_db_rec rec;
    char buf[2046];
    struct aura_iovec code;
    int rv;

    memset(buf, 0, sizeof(buf));
    code.base = NULL;
    code.len = 0;

    /*brokered */
    if (dmn_sock_fd != -1) {
        snprintf(buf, sizeof(buf), "%s:%s", name, version);
        key.base = buf;
        key.len = strlen(buf);

        if (aura_db_brokered_fetch(mc, A_NS_FN, A_FN_CODE_SCHEMA_ID, &key, &data_out, dmn_sock_fd) < 0)
            return code;

        code.base = data_out.base;
        code.len = data_out.len;
    } else {
        /* direct call */
        A_BUG_ON_2(!db, true);
        snprintf(buf, sizeof(buf), "%s:%s:%s:%s", A_DB_FN_KEY_PREFIX, name, version, A_DB_FN_CODE_SUFFIX);
        key.base = buf;
        key.len = strlen(buf);
        rv = aura_db_fetch(db, A_NS_FN, A_FN_CODE_SCHEMA_ID, &key, &rec);
        if (rv < 0 || rv == A_DB_REC_NOT_FOUND) {
            return code;
        }

        code.base = rec.data.base;
        code.len = rec.data.len;
    }

    return code;
}

int aura_fn_code_load(struct aura_fn *fn, struct aura_mem_ctx *mc, char *name,
                      char *version, AURA_DBHANDLE db, int dmn_sock_fd) {
    struct aura_iovec code = aura_fn_code_fetch(mc, name, version, db, dmn_sock_fd);

    if (!code.base)
        return -1;

    /* transfer ownership of function */
    fn->fn_code = (void *)code.base;
    fn->fn_code_len = code.len;
    fn->backend = 1; /* JS backend */
    return 0;
}

int aura_fn_load(struct aura_fn *fn, struct aura_mem_ctx *mc, char *name,
                 char *version, AURA_DBHANDLE db, int dmn_sock_fd) {
    /* Assumes meta has already been loaded */
    if (aura_fn_config_load(fn, mc, name, version, NULL, dmn_sock_fd) < 0)
        return -1;

    if (aura_fn_stat_load(fn, mc, name, version, NULL, dmn_sock_fd) < 0)
        return -1;

    if (aura_fn_code_load(fn, mc, name, version, NULL, dmn_sock_fd) < 0)
        return -1;

    if (aura_fn_state_load(fn, mc, name, version, NULL, dmn_sock_fd) < 0)
        return -1;

    return 0;
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
    if (fn_conf->triggers.cnt > 0) {
        app_debug(true, 0, "    Triggers");
        for (int i = 0; i < fn_conf->triggers.cnt; ++i) {
            switch (fn_conf->triggers.entries[i].trigger) {
            case A_FN_TRIGGER_HTTP:
                app_debug(true, 0, "    Http Trigger");
                app_debug(true, 0, "        Path=%s", fn_conf->triggers.entries[i].http.path.base);
                app_debug(true, 0, "        Method=%d", fn_conf->triggers.entries[i].http.method);
                break;
            }
        }
    } else {
        app_debug(true, 0, "     No func triggers registered");
    }
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

void aura_fn_dump_fn_tag(struct aura_fn_tag *tag) {
    app_debug(true, 0, "AURA FN TAG");
    app_debug(true, 0, "    FN Id=%zu", tag->fn_id);
    app_debug(true, 0, "    FN Name=%s", tag->fn_name);
    app_debug(true, 0, "    FN Version=%s", tag->fn_version);
    app_debug(true, 0, "    Deployed at: %zu", tag->timestamp_ms);
}
