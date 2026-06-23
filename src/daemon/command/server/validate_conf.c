// #include "blobber/lib.h"
#include "command/server.h"
#include "error_lib.h"
#include "file/lib.h"
#include "picotls.h"
#include "picotls/openssl.h"
#include "unix/sock.h"
#include "utils_lib.h"
#include "yaml/lib.h"

#include <arpa/inet.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
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
void a_yml_validate_fn_version(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_yml_node *yn) {
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
void a_yml_validate_server_info(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_yml_node *yn) {
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

    /* timeout map */
    if (strcmp(yn->key, "timeout") == 0) {
        a_ensure_node_is_mapping(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NONE, A_IDX_SERVER_NONE);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* timeout.read */
    if (strcmp(yn->key, "read") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_SERVER_READ_TO);
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
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_SERVER_WRITE_TO);
            usr_data->node_arr[node_off].str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }
}

typedef enum {
    A_FIELD_ADDR,
    A_FIELD_PORT,
    A_FIELD_PROTOCOL,
    A_FIELD_TLS,
    A_FIELD_QUIC
} a_listener_field_type;

/* Fill the listener array */
static inline int a_listener_append(struct aura_yml_srv_listeners *listeners, int idx, a_listener_field_type field_type, void *val) {
    /* touching this index position for the first time */
    bool first_visit = listeners->cnt != idx + 1;
    /* count driven by yaml index */
    listeners->cnt = idx + 1;

    while (listeners->cap <= listeners->cnt) {
        listeners->cap = listeners->cap == 0 ? 3 : listeners->cap * 2;
        listeners->entries = realloc(listeners->entries, sizeof(*listeners->entries) * listeners->cap);
        if (!listeners->entries)
            return -1;
    }

    /* set default values if first visit */
    if (first_visit) {
        listeners->entries[idx].address = A_ADDR_UNSET_IPV4;
        listeners->entries[idx].port = A_PORT_UNSET;
        listeners->entries[idx].protocol = A_PROTOCOL_NONE;
        listeners->entries[idx].tls = false;
        listeners->entries[idx].quic = false;
    }

    switch (field_type) {
    case A_FIELD_ADDR:
        listeners->entries[idx].address = *(uint64_t *)val;
        break;

    case A_FIELD_PORT:
        listeners->entries[idx].port = *(uint16_t *)val;
        break;

    case A_FIELD_PROTOCOL:
        listeners->entries[idx].protocol = *(a_transport_protocol *)val;
        break;

    case A_FIELD_TLS:
        listeners->entries[idx].tls = *(bool *)val;
        break;

    case A_FIELD_QUIC:
        listeners->entries[idx].quic = *(bool *)val;
        break;

    default:
        return -1;
    }

    return 0;
}

/* ---------- LISTENERS ---------- */
void a_yml_validate_listeners(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_yml_node *yn) {
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

    if (strcmp(yn->key, "listeners") == 0) {
        a_ensure_node_is_sequence(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NONE, A_IDX_SERVER_LISTENERS);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    if (strcmp(yn->key, "listeners[*]") == 0) {
        a_ensure_node_is_mapping(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NONE, A_IDX_SERVER_NONE);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    if (strcmp(yn->key, "name") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_SERVER_NONE);
            usr_data->node_arr[node_off].str_val = yn->str_val ? strdup(yn->str_val) : NULL;
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* address */
    if (strcmp(yn->key, "address") == 0) {
        uint32_t addr;

        a_ensure_node_is_scalar(p, evt, yn);

        if (inet_pton(AF_INET, yn->str_val, &addr) != 1)
            YAML_ADD_ERROR(p, evt, "Invalid %s, Expected a valid address", yn->full_path);

        if (a_listener_append(&usr_data->listeners, yn->idx, A_FIELD_ADDR, (void *)&addr) < 0)
            YAML_ADD_ERROR(p, evt, "Internal validation error: %s", yn->full_path);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_SERVER_NONE);
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
         * Scan with 32 bits to be able to detect invalid port
         * beyond 65536.
         */
        res = aura_scan_str(yn->str_val, "%" SCNu32, &port);
        if (res != 1 || port > UINT16_MAX)
            YAML_ADD_ERROR(p, evt, "Invalid %s, Expected a valid port number", yn->full_path);

#ifdef AURA_DEV_BUILD
        if (port < 1024)
            YAML_ADD_ERROR(p, evt, "Invalid %s, Ports below 1024 are disallowed in Dev environment", yn->full_path);
#endif

        if (a_listener_append(&usr_data->listeners, yn->idx, A_FIELD_PORT, (void *)&port) < 0)
            YAML_ADD_ERROR(p, evt, "Internal validation error: %s", yn->full_path);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_SERVER_NONE);
            usr_data->node_arr[node_off].str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* protocol */
    if (strcmp(yn->key, "protocol") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);
        int is_tcp = strcasecmp(yn->str_val, "tcp") == 0;
        int is_udp = strcasecmp(yn->str_val, "udp") == 0;

        if (!is_tcp && !is_udp != 0)
            YAML_ADD_ERROR(p, evt, "Invalid listener protocol, expected 'tcp' or 'udp");

        /* Not supported as yet! */
        if (is_udp)
            YAML_ADD_ERROR(p, evt, "UDP/QUIC protocol not yet supported");

        int proto = is_tcp ? A_PROTOCOL_TCP : is_udp ? A_PROTOCOL_UDP
                                                     : A_PROTOCOL_NONE;
        if (a_listener_append(&usr_data->listeners, yn->idx, A_FIELD_PROTOCOL, (void *)&proto) < 0)
            YAML_ADD_ERROR(p, evt, "Internal validation error: %s", yn->full_path);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NUM, A_IDX_SERVER_NONE);
            usr_data->node_arr[node_off].int_val = proto;
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* tls status */
    if (strcmp(yn->key, "tls") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);
        int is_true = strcasecmp(yn->str_val, "true") == 0;
        int is_false = strcasecmp(yn->str_val, "false") == 0;

        if (!is_true && !is_false != 0)
            YAML_ADD_ERROR(p, evt, "Invalid listener tls configuration, expected 'true' or 'false");

        bool tls = is_true ? true : false;
        if (a_listener_append(&usr_data->listeners, yn->idx, A_FIELD_TLS, (void *)&tls) < 0)
            YAML_ADD_ERROR(p, evt, "Internal validation error: %s", yn->full_path);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_BOOL, A_IDX_SERVER_NONE);
            usr_data->node_arr[node_off].bool_val = tls;
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* quic status */
    if (strcmp(yn->key, "quic") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);
        int is_true = strcasecmp(yn->str_val, "true") == 0;
        int is_false = strcasecmp(yn->str_val, "false") == 0;

        if (!is_true && !is_false != 0)
            YAML_ADD_ERROR(p, evt, "Invalid listener quic configuration, expected 'true' or 'false");

        bool quic = is_true ? true : false;
        if (a_listener_append(&usr_data->listeners, yn->idx, A_FIELD_QUIC, (void *)&quic) < 0)
            YAML_ADD_ERROR(p, evt, "Internal validation error: %s", yn->full_path);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_BOOL, A_IDX_SERVER_NONE);
            usr_data->node_arr[node_off].bool_val = quic;
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }
}

/* Fill the listener array */
static inline int a_listener_tls_tag(struct aura_yml_tls_tags *tags, int idx, char *val) {
    /* count driven by yaml index */
    tags->cnt = idx + 1;

    while (tags->cap <= tags->cnt) {
        tags->cap = tags->cap == 0 ? 3 : tags->cap * 2;
        tags->entries = realloc(tags->entries, sizeof(*tags->entries) * tags->cap);
        if (!tags->entries)
            return -1;
    }

    tags->entries[idx] = strdup(val);

    return 0;
}

/*---------- TLS ----------*/
void a_yml_validate_tls(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_yml_node *yn) {
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
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NONE, A_IDX_SERVER_NONE);
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
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NONE, A_IDX_SERVER_TLS_IDEN);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    /* identities[*] */
    if (strcmp(yn->key, "identities[*]") == 0) {
        a_ensure_node_is_mapping(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NONE, A_IDX_SERVER_NONE);
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
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_SERVER_NONE);
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
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_SERVER_NONE);
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

        /* update tls seen on the first tag */
        if (!usr_data->seen_tls_identities)
            usr_data->seen_tls_identities = true;

        if (a_listener_tls_tag(&usr_data->tls_tags, yn->idx, (char *)yn->str_val) < 0)
            YAML_ADD_ERROR(p, evt, "Internal validation error: %s", yn->full_path);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_SERVER_NONE);
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
                a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_SERVER_NONE);
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
                a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NONE, A_IDX_SERVER_TLS_CIPHERS);
                usr_data->node_arr[node_off].str_val = NULL;
                a_parse_tree_insert(p, evt, yn, node_off);
            }
        }
        return;
    }
}

typedef enum {
    A_FIELD_HOST_NAME,
    A_FIELD_HOST_TLS,
} a_host_field_type;

/* Fill the listener array */
static inline int a_host_append(struct aura_yml_srv_hosts *hosts, int idx, a_host_field_type field_type, void *val) {
    /* touching this index position for the first time */
    bool first_visit = hosts->cnt != idx + 1;
    /* count driven by yaml index */
    hosts->cnt = idx + 1;

    while (hosts->cap <= hosts->cnt) {
        hosts->cap = hosts->cap == 0 ? 3 : hosts->cap * 2;
        hosts->entries = realloc(hosts->entries, sizeof(*hosts->entries) * hosts->cap);
        if (!hosts->entries)
            return -1;
    }

    /* set default values if first visit */
    if (first_visit) {
        hosts->entries[idx].name = NULL;
        hosts->entries[idx].tls_tag = NULL;
    }

    switch (field_type) {
    case A_FIELD_HOST_NAME:
        hosts->entries[idx].name = strdup(val);
        break;

    case A_FIELD_HOST_TLS:
        hosts->entries[idx].tls_tag = strdup(val);
        break;

    default:
        return -1;
    }

    return 0;
}

/*---------- HOST ----------*/
void a_yml_validate_hosts(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_yml_node *yn) {
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
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NONE, A_IDX_SERVER_HOSTS);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    if (strcmp(yn->key, "hosts[*]") == 0) {
        a_ensure_node_is_mapping(p, evt, yn);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_NONE, A_IDX_SERVER_NONE);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    if (strcmp(yn->key, "name") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);

        if (a_host_append(&usr_data->hosts, yn->idx, A_FIELD_HOST_NAME, (void *)yn->str_val) < 0)
            YAML_ADD_ERROR(p, evt, "Internal validation error: %s", yn->full_path);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_SERVER_NONE);
            usr_data->node_arr[node_off].str_val = strdup(yn->str_val);
            a_parse_tree_insert(p, evt, yn, node_off);
        }
        return;
    }

    if (strcmp(yn->key, "tls") == 0) {
        a_ensure_node_is_scalar(p, evt, yn);

        if (a_host_append(&usr_data->hosts, yn->idx, A_FIELD_HOST_TLS, (void *)yn->str_val) < 0)
            YAML_ADD_ERROR(p, evt, "Internal validation error: %s", yn->full_path);

        if (usr_data->extract && !p->in_panic) {
            node_off = a_get_node_off(p, evt);
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_SERVER_NONE);
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
            a_init_yaml_node(usr_data->node_arr[node_off], yn->type, yn->key, A_YAML_STRING, A_IDX_SERVER_NONE);
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
static void a_run_parent_validator(struct aura_yml_conf_parser *p, yaml_event_t *evt, struct aura_yml_node *yn) {
    struct aura_yml_usr_data_ctx *usr_data;
    struct aura_yml_srv_listeners listeners;
    struct aura_yml_srv_hosts hosts;
    bool tls_supported;
    int i;

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

    /* validate listeners */
    listeners = usr_data->listeners;
    tls_supported = false;
    for (i = 0; i < listeners.cnt; ++i) {
        if (listeners.entries[i].address == A_ADDR_UNSET_IPV4 || listeners.entries[i].port == A_PORT_UNSET || listeners.entries[i].protocol == A_PROTOCOL_NONE) {
            YAML_ADD_ERROR(p, evt, "Invalid listener configuration, missing required fields");
            return;
        }

        if (listeners.entries[i].protocol == A_PROTOCOL_UDP && !listeners.entries[i].quic) {
            YAML_ADD_ERROR(p, evt, "Invalid listener configuration, UDP requries QUIC");
            return;
        }

        if (listeners.entries[i].protocol == A_PROTOCOL_UDP && listeners.entries[i].tls) {
            YAML_ADD_ERROR(p, evt, "Invalid listener configuration, TLS not valid for UDP");
            return;
        }

        if ((listeners.entries[i].tls || listeners.entries[i].quic) && !tls_supported)
            tls_supported = true;

        /* Penalize complete duplicates on tcp */
        for (int j = 0; j < listeners.cnt; ++j) {
            if (j != i) {
                if (listeners.entries[j].address == listeners.entries[i].address &&
                    listeners.entries[j].port == listeners.entries[i].port &&
                    listeners.entries[j].protocol == listeners.entries[i].protocol &&
                    listeners.entries[j].protocol == A_PROTOCOL_TCP) {
                    YAML_ADD_ERROR(p, evt, "Invalid listener configuration, Duplicate tcp connection not allowed");
                    return;
                }
            }
        }
    }

    /* Validate identities */
    if (tls_supported && !usr_data->seen_tls_identities) {
        YAML_ADD_ERROR(p, evt, "TLS identity required to support TLS listeners");
        return;
    }

    /* Validate hosts */
    hosts = usr_data->hosts;
    bool tag_seen;
    for (i = 0; i < hosts.cnt; ++i) {
        if (!hosts.entries[i].name || (tls_supported && !hosts.entries[i].tls_tag)) {
            YAML_ADD_ERROR(p, evt, "Invalid host configuration missing required fields");
            return;
        }

        /* search for host tls tag */
        tag_seen = false;
        for (int j = 0; j < usr_data->tls_tags.cnt; ++j) {
            if (strcmp(hosts.entries[i].tls_tag, usr_data->tls_tags.entries[j]) == 0 && tls_supported)
                tag_seen = true;
        }
        if (!tag_seen && tls_supported) {
            YAML_ADD_ERROR(p, evt, "Invalid hosts configuration, unknown tls identity for hosts: %s", hosts.entries[i].name);
            return;
        }
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
  {"version", .cb = a_yml_validate_fn_version},
  {"server", .cb = a_yml_validate_server_info},
  {"listeners", .cb = a_yml_validate_listeners},
  {"tls", .cb = a_yml_validate_tls},
  {"hosts", .cb = a_yml_validate_hosts},
  {"logging", NULL},
  {"monitoring", NULL},
  {"security", NULL},
  {"parent_validator", .cb = a_run_parent_validator}, /* position parent validator as last array entry */
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
    int i;

    if (!usr_data)
        return;

    if (usr_data->listeners.entries) {
        free(usr_data->listeners.entries);
    }

    /* Underlying host name is freed by yaml below */
    for (i = 0; i < usr_data->hosts.cnt; ++i) {
        if (usr_data->hosts.entries[i].name)
            free(usr_data->hosts.entries[i].name);

        if (usr_data->hosts.entries[i].tls_tag)
            free(usr_data->hosts.entries[i].tls_tag);
    }

    for (i = 0; i < usr_data->node_cnt; ++i) {
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
void aura_dmn_validate_server_conf(int config_fd, int cli_fd) {
    struct aura_yml_usr_data_ctx usr_data;
    struct aura_yml_err_ctx *parser_err;
    bool fail_fast = true, extract = false;
    int res;
    const char *first_err = NULL;

    parser_err = aura_create_yml_error_ctx(fail_fast);
    a_srv_init_user_data_ctx(&usr_data, extract);

    res = aura_load_config_fd(config_fd, aura_server_validator, aura_server_validator_len, parser_err, (void *)&usr_data);
    if (res != 0 && parser_err->err_cnt > 0) {
        first_err = parser_err->errors[0].message;
        aura_resp_send(cli_fd, (void *)first_err, strlen(first_err));
    } else {
        aura_resp_send(cli_fd, (void *)config_valid, sizeof(config_valid) - 1);
    }

    close(cli_fd);
    aura_free_yml_error_ctx(parser_err);
    a_srv_free_user_data_ctx(&usr_data);
}
