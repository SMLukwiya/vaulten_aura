#include "blobber_lib.h"
#include "command/server_dmn.h"
#include "error_lib.h"
#include "file_lib.h"
#include "picotls.h"
#include "picotls/openssl.h"
#include "unix_socket_lib.h"
#include "utils_lib.h"
#include "yaml_lib.h"

#include <arpa/inet.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

/**
 * Expects field name, value expected and value parsed in that order
 */
const char config_valid[] = "\x1B[1;32mConfig valid\x1B[0m";
const char invalid_single_field_format[] = "Invalid %s, Expected value to be %s but got %s";

/**
 * Get a slot for a yaml node in the yaml node pool
 */
static inline uint32_t a_get_node_off(struct aura_yml_conf_parser *p, yaml_event_t *evt) {
    struct aura_yml_usr_data_ctx *us;

    us = (struct aura_yml_usr_data_ctx *)p->usr_data_ctx;

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
    struct aura_yml_usr_data_ctx *us;
    aura_rax_tree_t *t;
    int res;

    us = (struct aura_yml_usr_data_ctx *)p->usr_data_ctx;
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

/*----------- AURA YAML VERSION -----------*/
void a_validate_yaml_version_fn(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_yml_node *yn) {
    struct aura_yml_usr_data_ctx *usr_data;
    const char *value = evt->data.scalar.value;

    usr_data = (struct aura_yml_usr_data_ctx *)p->usr_data_ctx;

    a_ensure_node_is_scalar(p, evt, yn);
    if (!value || strlen(value) == 0) {
        YAML_ADD_ERROR(p, evt, invalid_single_field_format, "yaml version", "v1beta1", "empty string");
        return;
    }

    if (strcmp(value, "v1beta1") != 0)
        YAML_ADD_ERROR(p, evt, invalid_single_field_format, "yaml version", "v1beta1", value);

    usr_data->seen_aura_version = true;
}

/*---------- SERVER ----------*/
void a_validate_yml_server(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_yml_node *yn) {
    struct aura_yml_usr_data_ctx *usr_data;
    aura_rax_tree_t *rax;
    uint32_t node_off;
    int res;

    usr_data = (struct aura_yml_usr_data_ctx *)p->usr_data_ctx;
    rax = usr_data->parse_tree;

    if (!yn) {
        app_alert(true, 0, "Validation node not passed: fix asap");
        return;
    }

    if (usr_data->extract && !rax) {
        app_alert(true, 0, "Trying to extract data without parser tree!: fix asap");
        return;
    }

    /* server starting map */
    if (strcmp(yn->key, "server") == 0) {
        a_ensure_node_is_mapping(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            usr_data->node_arr[node_off].type = yn->type;
            usr_data->node_arr[node_off].key = strdup(yn->key);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* name */
    if (strcmp(yn->key, "name") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_SERVER_NAME);
            usr_data->node_arr[node_off].str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* port */
    if (strcmp(yn->key, "port") == 0) {
        uint32_t port;

        a_ensure_node_is_scalar(p, evt, yn);

        /**
         * Scan with 32 bits so we can detect larger numbers
         * otherwise 16 bits would wrap around and we wouldn't
         * detect.
         */
        res = aura_scan_str(yn->str_val, "%" SCNu32, &port);
        if (res != 1 || port > UINT16_MAX)
            YAML_ADD_ERROR(p, evt, "Invalid %s, Expected a valid port number", yn->full_path);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NUM, A_IDX_SERVER_PORT);
            usr_data->node_arr[node_off].uint_val = port;
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* address */
    if (strcmp(yn->key, "addr") == 0) {
        uint32_t addr;

        a_ensure_node_is_scalar(p, evt, yn);

        if (inet_pton(AF_INET, yn->str_val, &addr) != 1)
            YAML_ADD_ERROR(p, evt, "Invalid %s, Expected a valid address", yn->full_path);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NUM, A_IDX_SERVER_ADDR);
            usr_data->node_arr[node_off].uint_val = addr;
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* timeout map */
    if (strcmp(yn->key, "timeout") == 0) {
        a_ensure_node_is_mapping(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NONE, A_IDX_NONE);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* timeout.read */
    if (strcmp(yn->key, "read") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_SERVER_TO_READ);
            usr_data->node_arr[node_off].str_val = strdup(yn->str_val);
            // usr_data->node_arr[node_off].val_type = A_YAML_STRING; /** @todo: maybe number */
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* timeout.write */
    if (strcmp(yn->key, "write") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {

            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_SERVER_TO_WRITE);
            usr_data->node_arr[node_off].str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }
}

/*---------- TLS ----------*/
void a_validate_yml_tls(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_yml_node *yn) {
    struct aura_yml_usr_data_ctx *usr_data;
    aura_rax_tree_t *rax;
    uint32_t node_off;
    int res;

    usr_data = (struct aura_yml_usr_data_ctx *)p->usr_data_ctx;
    rax = usr_data->parse_tree;

    if (!yn) {
        app_alert(true, 0, "Validation node not passed: fix asap");
        return;
    }

    if (usr_data->extract && !rax) {
        app_alert(true, 0, "Trying to extract data without parser tree!: fix asap");
        return;
    }

    if (strcmp(yn->key, "tls") == 0) {
        a_ensure_node_is_mapping(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NONE, A_IDX_NONE);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* identities */
    if (strcmp(yn->key, "identities") == 0) {
        a_ensure_node_is_sequence(p, evt, yn);

        // should count be validated

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NONE, A_IDX_TLS_IDEN);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* identities[*] */
    if (strcmp(yn->key, "identities[*]") == 0) {
        a_ensure_node_is_mapping(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NONE, A_IDX_NONE);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* cert */
    if (strcmp(yn->key, "cert_file") == 0) {
        char resolved[1024];

        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->expect_key)
            YAML_ADD_ERROR(p, evt, "Expecting key file for previous cert file");

        res = aura_get_absolute_path(yn->str_val, resolved);
        if (res != 0)
            YAML_ADD_ERROR(p, evt, invalid_single_field_format, "tls cert file", "a valid path to cert file", "invalid path");

        res = access(resolved, R_OK);
        if (res < 0)
            YAML_ADD_ERROR(p, evt, "Failed to acquire read permissions for file: %s", resolved);

        /**
         * We set up some fake ssl cxt and use that to verify the
         * provided cert file
         */
        ERR_clear_error();
        usr_data->ssl_ctx = SSL_CTX_new(TLS_server_method());
        if (!usr_data->ssl_ctx) {
            app_debug(true, 0, "Failed to create fake ssl context for cert verification %s", ERR_error_string(ERR_get_error(), NULL));
            YAML_ADD_ERROR(p, evt, "Failed to setup cert verification for %s", resolved);
        }

        res = SSL_CTX_use_certificate_chain_file(usr_data->ssl_ctx, resolved);
        if (res <= 0) {
            app_debug(true, 0, "Failed to verify certificate chain fle %s", ERR_error_string(ERR_get_error(), NULL));
            SSL_CTX_free(usr_data->ssl_ctx);
            YAML_ADD_ERROR(p, evt, "Failed to verify cert chain file: %s", resolved);
        }

        usr_data->expect_key = true;
        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_NONE);
            usr_data->node_arr[node_off].str_val = strdup(resolved);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    if (strcmp(yn->key, "key_file") == 0) {
        EVP_PKEY *key;
        int res;
        char resolved[1024];

        a_ensure_node_is_scalar(p, evt, yn);

        if (!usr_data->ssl_ctx)
            YAML_ADD_ERROR(p, evt, "Failed to find cert file for this key, please define cert file before key file");

        res = aura_get_absolute_path(yn->str_val, resolved);
        if (res != 0) {
            YAML_ADD_ERROR(p, evt, invalid_single_field_format, "tls key file", "a valid path to key file", "invalid path");
            goto err_out;
        }

        res = access(resolved, R_OK);
        if (res < 0) {
            YAML_ADD_ERROR(p, evt, invalid_single_field_format, "tls key file", "a readable file", "failed read permission");
            goto err_out;
        }

        ERR_clear_error();
        res = SSL_CTX_use_PrivateKey_file(usr_data->ssl_ctx, resolved, SSL_FILETYPE_PEM);
        if (res <= 0) {
            app_debug(true, 0, "Failed to load key file: %s", ERR_error_string(ERR_get_error(), NULL));
            YAML_ADD_ERROR(p, evt, "Failed to load key file: %s", resolved);
            goto err_out;
        }

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_NONE);
            usr_data->node_arr[node_off].str_val = strdup(resolved);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        usr_data->seen_any_key_file = true;

    err_out:
        SSL_CTX_free(usr_data->ssl_ctx);
        usr_data->ssl_ctx = NULL;
        return;
    }

    if (strcmp(yn->key, "tag") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_NONE);
            usr_data->node_arr[node_off].str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    if (strcmp(yn->key, "cipher_suites") == 0) {
        ptls_cipher_suite_t *c;
        uint32_t i;

        if (yn->str_val) {
            a_ensure_node_is_scalar(p, evt, yn);

            for (i = 0; (c = ptls_openssl_cipher_suites_all[i]) != NULL; ++i) {
                if (strcmp(yn->str_val, c->name) == 0) {
                    /* found cipher */
                    if (c == &ptls_openssl_aes128gcmsha256)
                        usr_data->is_aes128gcmsha256_set = true; /* RFC 8446 9.1 stuff! */

                    goto proceed;
                }
            }
            char msg[1024];
            strcpy(msg, "Unexpected cipher suite. Expected one of: ");
            for (i = 0; ptls_openssl_cipher_suites_all[i] != NULL; ++i)
                sprintf(msg + strlen(msg), "%s, ", ptls_openssl_cipher_suites_all[i]->name);

            YAML_ADD_ERROR(p, evt, "%s", msg);
            return;
        proceed:
            if (usr_data->extract && !p->in_panic) {
                node_off = a_get_node_off(p, evt);
                a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_NONE);
                /**
                 * Since the same key is re-used for the sequence entries as well,
                 * we must check if we have a value associated with an entry,
                 * or if we are still at the beginning of the sequence.
                 */
                usr_data->node_arr[node_off].str_val = strdup(yn->str_val);
                a_parse_tree_insert(p, evt, yn, node_off);
            }
        } else {
            a_ensure_node_is_sequence(p, evt, yn);

            usr_data->seen_ciphers = true;
            if (usr_data->extract && !p->in_panic) {
                node_off = a_get_node_off(p, evt);
                a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NONE, A_IDX_TLS_CIPHERS);
                usr_data->node_arr[node_off].str_val = NULL;
                a_parse_tree_insert(p, evt, yn, node_off);
            }
        }
        return;
    }
}

/*---------- HOST ----------*/
/**
 * Validate hosts
 * hosts
 */
void a_validate_hosts(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_yml_node *yn) {
    struct aura_yml_usr_data_ctx *usr_data;
    aura_rax_tree_t *rax;
    uint32_t node_off;
    int res;

    usr_data = (struct aura_yml_usr_data_ctx *)p->usr_data_ctx;
    rax = usr_data->parse_tree;

    if (!yn) {
        app_alert(true, 0, "Validation node not passed");
        return;
    }

    if (usr_data->extract && !rax) {
        app_alert(true, 0, "Trying to extract data without parser tree!");
        return;
    }

    if (strcmp(yn->key, "hosts") == 0) {
        a_ensure_node_is_sequence(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NONE, A_IDX_HOSTS);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    if (strcmp(yn->key, "hosts[*]") == 0) {
        a_ensure_node_is_mapping(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            // usr_data->node_arr[node_off].type = yn->type;
            // usr_data->node_arr[node_off].key = strdup(yn->key);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NONE, A_IDX_NONE);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    if (strcmp(yn->key, "name") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_NONE);
            usr_data->node_arr[node_off].str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    if (strcmp(yn->key, "tls") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_NONE);
            usr_data->node_arr[node_off].str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    if (strcmp(yn->key, "http2_origin_frame") == 0) {
        if (yn->str_val)
            a_ensure_node_is_scalar(p, evt, yn);
        else
            a_ensure_node_is_sequence(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_NONE);
            /**
             * Since the same key is re used for the sequence entries as well,
             * we must check if we have a value associated with an entry,
             * or if we are still at the beginning of the sequence.
             */
            usr_data->node_arr[node_off].str_val = yn->str_val ? strdup(yn->str_val) : NULL;
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }
}

/**
 * Validator run at the end to check for
 * mostly missing fields
 */
static void a_run_parent_validator(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_validation_ctx *v_ctx) {
    struct aura_yml_usr_data_ctx *usr_data;
    usr_data = (struct aura_yml_usr_data_ctx *)p->usr_data_ctx;

    /* validate mandatory fields */
    if (!usr_data->seen_tls_identities) {
        YAML_ADD_ERROR(p, evt, "Did not find valid tls information, refer to docs for valid tls information struture");
        return;
    }

    if (!usr_data->seen_any_key_file) {
        YAML_ADD_ERROR(p, evt, "missing a key file, please provide one");
        return;
    }
}

/**
 * server yaml fields
 */
/*
struct aura_yml_validator aura_server_validator__[] = {
  {"version", {NULL}},
  {"server", {NULL}},
  {"server.name", {NULL}},
  {"server.environment", {NULL}},
  {"server.port", {NULL}},
  {"server.addr", {NULL}},
  {"server.max_connections", {NULL}},
  {"server.timeout", {NULL}},
  {"server.timeout.read", {NULL}},
  {"server.timeout.write", {NULL}},
  {"server.timeout.idle", {NULL}},
  {"tls", {NULL}},
  {"tls.identities", {NULL}},
  {"tls.identities[*].cert_file", {NULL}},
  {"tls.identities[*].key_file", {NULL}},
  {"tls.ciphers", {NULL}},
  {"tls.ciphers[*]", {NULL}},
  {"hosts", {NULL}},
  {"hosts[*].name", {NULL}},
  {"hosts[*].http2_origin_frame[-]", {NULL}},
  {"logging", {NULL}},
  {"logging.level", {NULL}},
  {"logging.format", {NULL}},
  {"logging.output", {NULL}},
  {"logging.rotation", {NULL}},
  {"logging.rotation.max_size", {NULL}},
  {"logging.rotation.max_age", {NULL}},
  {"logging.rotation.max_backups", {NULL}},
  {"logging.rotation.compress", {NULL}},
  {"monitoring", {NULL}},
  {"monitoring.metrics", {NULL}},
  {"monitoring.metrics.enabled", {NULL}},
  {"monitoring.metrics.endpoint", {NULL}},
  {"monitoring.metrics.port", {NULL}},
  {"monitoring.healthcheck", {NULL}},
  {"monitoring.healthcheck.interval", {NULL}},
  {"monitoring.healthcheck.timeout", {NULL}},
  {"monitoring.healthcheck.path", {NULL}},
  {"security", {NULL}},
  {"security.rate_limit", {NULL}},
  {"security.rate_limit.enabled", {NULL}},
  {"security.rate_limit.requests_per_second", {NULL}},
  {"security.rate_limit.burst", {NULL}},
  {"no_path_validator", {NULL}},
};*/

/**
 *
 */
struct aura_yml_validator aura_server_validator[] = {
  {"version", .cb = a_validate_yaml_version_fn},
  {"server", .cb = a_validate_yml_server},
  {"tls", .cb = a_validate_yml_tls},
  {"hosts", .cb = a_validate_hosts},
  {"logging", NULL},
  {"monitoring", NULL},
  {"security", NULL},
  //   {"no_path_validator", .cb = a_run_parent_validator},
};

int aura_server_validator_len = ARRAY_SIZE(aura_server_validator);

/**
 *
 */
void a_srv_init_user_data_ctx(struct aura_yml_usr_data_ctx *usr_data, bool extract) {
    memset(usr_data, 0, sizeof(*usr_data));
    usr_data->extract = extract;

    if (usr_data->extract) {
        usr_data->parse_tree = aura_rax_new();
        aura_blob_builder_init(&usr_data->builder);
    }
}

void a_srv_free_user_data_ctx(struct aura_yml_usr_data_ctx *usr_data) {
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
void aura_dmn_server_config_validate(int conf_fd, int cli_fd) {
    struct aura_yml_usr_data_ctx usr_data;
    struct aura_yml_err_ctx *parser_err;
    bool fail_fast = true, extract = false;
    int res;
    const char *first_err = NULL;

    parser_err = aura_create_yml_error_ctx(fail_fast);
    a_srv_init_user_data_ctx(&usr_data, extract);

    res = aura_load_config_fd(conf_fd, aura_server_validator, aura_server_validator_len, parser_err, (void *)&usr_data);
    if (res != 0 && parser_err->err_cnt > 0) {
        first_err = parser_err->errors[0].message;
        aura_send_resp(cli_fd, (void *)first_err, strlen(first_err));
    } else {
        aura_send_resp(cli_fd, (void *)config_valid, sizeof(config_valid) - 1);
    }

    close(cli_fd);
    aura_free_yml_error_ctx(parser_err);
    a_srv_free_user_data_ctx(&usr_data);
}
