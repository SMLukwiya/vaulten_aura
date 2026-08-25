#ifndef AURA_FUNCTION_LIB_H
#define AURA_FUNCTION_LIB_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>

#include "blobber/lib.h"
#include "db/db.h"
#include "error_lib.h"
#include "hashmap/map.h"
#include "heap/lib.h"
#include "memory/lru_cache.h"
#include "radix/tree.h"
#include "task_queue/tq.h"
#include "time_lib.h"
#include "types_lib.h"
#include "utils_lib.h"

#define A_FN_NAME_MAX_LEN 128
#define A_FN_VERSION_MAX_LEN 32
#define A_FN_DEFAULT_VERSION "1.0.0"
#define A_FN_MAX_REGISTRY_CNT 32
#define A_FN_MAX_TRIGGERS 8

/* Namespace prefixes */
#define A_DB_FN_KEY_PREFIX "fn"

/* Resource type suffixes */
#define A_DB_FN_META_SUFFIX "meta"
#define A_DB_FN_CODE_SUFFIX "code"
#define A_DB_FN_CONF_SUFFIX "config"
#define A_DB_FN_STAT_SUFFIX "stat"
#define A_DB_FN_STATE_SUFFIX "state"

#define A_FN_LIST_KEY "system:functions"

enum aura_fn_cache_id {
    A_FN_SLAB_CACHE_ID = A_SLAB_CACHE_FN_BASE + 1
};

/* Namespaces */
typedef enum {
    A_NS_FN = A_DB_FN_BASE + 1, /* Function namespace */
} aura_fn_db_namespace;

/* Schemas */
typedef enum {
    A_FN_CODE_SCHEMA_ID = A_DB_FN_BASE + 1,
    A_FN_META_SCHEMA_ID,
    A_FN_CONF_SCHEMA_ID,
    A_FN_STAT_DELTA_SCHEMA_ID,
    A_FN_TAG_SCHEMA_ID,
    A_FN_STATE_SCHEMA_ID,
    A_FN_LIST_SCHEMA_ID,
} aura_fn_db_schema_id;

/* Fn list key (base, len) */
static struct aura_iovec a_function_list_key = {
  .base = "system:functions",
  .len = sizeof("system:functions") - 1,
};

#define MAX_CIRCUIT_BREAKER_TRIGGERS 3

#define aura_fn_async_op_wait(done) \
    while (!done)                   \
        ;

struct aura_fn_cb_data {
    uint64_t job_id;
    const char *fn_name;
    uint32_t fn_version;
};

typedef enum {
    A_FN_DEPLOY = 1U < 1,
    A_FN_DELETE = 1U < 2,
} aura_fn_tx_type;

enum a_fn_node_idx {
    A_IDX_FN_NONE,
    A_IDX_FN_FUNCTION,
    A_IDX_FN_NAME,
    A_IDX_FN_DESCRIPTION,
    A_IDX_FN_VERSION,
    A_IDX_FN_ID,
    A_IDX_FN_HOST,
    A_IDX_FN_ENTRY_POINT,
    A_IDX_FN_ENV,
    A_IDX_FN_TRIGGERS,
    A_IDX_FN_HTTP_TRIGGER,
    A_IDX_FN_CRON_TRIGGER,
    A_IDX_FN_QUEUE_TRIGGER,
    A_IDX_FN_CONCURRENCY,
    A_IDX_FN_MIN_INSTANCES,
    A_IDX_FN_MAX_INSTANCES,
    A_IDX_FN_PREWARM,
    A_IDX_FN_CRON_RETRIES,
    A_IDX_FN_RESOURCES,
    A_IDX_FN_MEMORY,
    A_IDX_FN_SOFT_MEM,
    A_IDX_FN_HARD_MEM,
    A_IDX_FN_OOM_POLICY,
    A_IDX_FN_NETWORKING,
};

/*--------------*/
struct aura_yml_fn_data_ctx {
    int dir_fd; /* function directory fd */
    bool seen_aura_version;
    bool extract;
    uint32_t trigger_type;
    aura_rax_tree_t parse_tree;
    st_aura_b_builder builder;
    struct {
        struct aura_yml_node *entries;
        uint32_t cnt;
        uint32_t cap;
    } node_vec;
    uint32_t node_len;
};

/* Runtime */
typedef enum {
    JIT = 1,
    NATIVE,
    WASM
} aura_runtime_t;

struct aura_fn_runtime {
    const char *str;
    aura_runtime_t value;
};

extern const struct aura_fn_runtime runtimes[];

/* Triggers */
typedef enum {
    A_FN_TRIGGER_HTTP = 1,
    A_FN_TRIGGER_CRON,
    A_FN_TRIGGER_QUEUE
} aura_trigger_t;

struct aura_fn_trigger {
    const char *str;
    aura_trigger_t value;
};

extern const struct aura_fn_trigger trigger_types[];

/* HTTP */
typedef enum {
    GET = 1,
    POST,
    PUT,
    PATCH,
    DELETE,
    HEAD
} aura_fn_http_method_t;

struct aura_fn_http_method {
    const char *str;
    aura_fn_http_method_t value;
};

extern const struct aura_fn_http_method http_methods[];

/* Cron */
/* Cron misfire policy */
typedef enum {
    FIRE_NOW = 1, /* Execute missed jobs immediately when possible */
    IGNORE,       /* Drop missed execution and wait for next schedule */
    RESCHEDULE    /* Run the job at the next possible time while maintaining original schedule */
} aura_fn_cron_misfire_policy_t;

struct aura_fn_cron_misfire_policy {
    const char *str;
    aura_fn_cron_misfire_policy_t value;
};

extern const struct aura_fn_cron_misfire_policy misfire_policies[];

/* Cron backoff */
typedef enum {
    BACKOFF_NONE,
    BACKOFF_FIXED,
    BACKOFF_EXPONENTIAL
} aura_fn_backoff_strategy_t;

struct aura_fn_backoff {
    const char *str;
    aura_fn_backoff_strategy_t value;
};

extern const struct aura_fn_backoff backoff_opt[];

/* Log level */
typedef enum {
    TRACE = 1,
    INFO,
    DEBUG,
    WARN,
    ERROR
} aura_fn_log_level_t;

struct aura_fn_log_level {
    const char *str;
    aura_fn_log_level_t value;
};

extern const struct aura_fn_log_level log_levels[];

/* Resources OOM policy */
typedef enum {
    KILL = 1,
    SNAPSHOT_THEN_KILL,
    THROTTLE
} aura_fn_oom_policy_t;

struct aura_fn_oom_policy {
    const char *str;
    aura_fn_oom_policy_t value;
};

extern const struct aura_fn_oom_policy oom_policies[];

/**
 * Controls for logging, tracing, and custom metrics.
 */
typedef enum {
    PII_DEFAULT = 1,
    REDACT_STRICT,
    REDACT_NONE
} aura_fn_log_redact_level_t;

struct aura_fn_log_redact_level {
    const char *str;
    aura_fn_log_redact_level_t value;
};

extern const struct aura_fn_log_redact_level log_redact_levels[];

/** Deployment strategy */
typedef enum {
    CANARY = 1,
    BLUE_GREEN,
    ROLLING
} aura_fn_deployment_strategy_t;

struct aura_fn_deployment_strategy {
    const char *str;
    aura_fn_deployment_strategy_t value;
};

extern const struct aura_fn_deployment_strategy deploy_strategies[];

typedef enum {
    BLUE = 1,
    GREEN
} aura_fn_blue_green_strategy_t;

struct aura_fn_blue_green {
    const char *str;
    aura_fn_blue_green_strategy_t value;
};

/** Network policy */
typedef enum {
    ALLOW_ALL = 1,
    DENY_ALL,
    WHITELIST
} aura_network_policy_t;

struct aura_fn_network_policy {
    const char *str;
    aura_network_policy_t value;
};

extern const struct aura_fn_network_policy network_policies[];

/** Network protocol */
typedef enum {
    TCP = 1,
    UDP
} aura_protocol_t;

struct aura_fn_protocol {
    const char *str;
    aura_protocol_t value;
};

typedef enum {
    TLS_1_3
} aura_tls_version_t;

typedef enum {
    NONE,
    JWT,
    MTLS,
    CUSTOM
} aura_auth_t;

/* Fn concurrency structure */
struct aura_fn_concurrency {
    uint32_t min_instances;  /* Min concurrent instances to be alive at all time */
    uint32_t max_instances;  /* The max number of concurrent instances for this function. */
    uint32_t delay;          /* Time between new instance spin up until max instances */
    bool pre_warm_on_deploy; /* create function ready instance(s) on deploy */
    bool background_tasks;   /* Enables the API for this function to submit background tasks. */
};

struct aura_fn_resources {
    uint32_t memory_limit_mb_soft;        /* Soft memory limit MBs */
    uint32_t memory_limit_mb_hard;        /* Hard memory limit MBs */
    uint32_t cpu_shares;                  /* Relative CPU share compared to other functions. */
    uint32_t timeout;                     /* The max execution time for a single invocation of the function in ms. */
    uint32_t cpu_burst_credit;            /* Internal: function can exceed their cpu limits based on good behaviour */
    uint32_t io_net_egress_bytes_per_sec; /* Internal: Amount of data leaving the network because of this function */
    uint32_t socket_max;                  /* Internal: */
    const struct aura_fn_oom_policy *oom_policy;
};

/**
 * NETWORK CONNECTION
 */
struct aura_fn_ingress {
    char **ip_whitelist; /* A list of IP addresses or CIDR blocks allowed to invoke the function. */
    size_t whitelsit_len;
    aura_network_policy_t policy; /* The default inbound network policy. */
};

struct aura_fn_egress_connection {
    const char *host;
    uint16_t port;
    aura_protocol_t protocol;
    aura_tls_version_t prot_version;
    bool secure;
    uint32_t idle_ttl;
    uint32_t max_per_origin;
};

struct aura_fn_egress {
    struct aura_fn_egress_connection **hosts; /* A list of IP addresses or CIDR blocks allowed to invoke the function. */
    size_t whitelist_len;
    aura_network_policy_t policy; /* The default outbound network policy. */
};

struct aura_fn_logging {
    char *destination;         /* The URL or identifier of the external logging service. */
    aura_fn_log_level_t level; /* The minimum logging level to output. */
    aura_fn_log_redact_level_t log_redact;
};

struct aura_fn_tracing {
    bool enabled;    /* Distributed tracing for the function. */
    int sample_rate; /* The rate at which to sample traces (0.0 to 1.0). */
    /**
     * INTERNAL
     * We should trace all requests that exceed this latency,
     * while only sampling the 'sample_rate' requests below it.
     */
    uint32_t tail_sampling_target_ms;
};

struct aura_fn_observability {
    struct aura_fn_logging fn_logging;
    struct aura_fn_tracing fn_tracing;
    bool custom_metrics;
};

struct aura_fn_deployment {
    aura_fn_deployment_strategy_t strategy;
    union {
        uint8_t percentage;
        uint32_t batch;
        aura_fn_blue_green_strategy_t primary;
    };
};

struct aura_fn_success_rules {
    uint32_t min_availability;
    uint32_t p95_latency_lt;
    uint8_t error_rate;
};

struct aura_fn_success_ctx {
    const char *health_check;
    struct aura_fn_success_rules rules;
    uint32_t rollback_after;
};

/* ---------- RELIABILITY ---------- */
/* Fn retry structure */
struct aura_fn_retry {
    uint32_t attempts;
    aura_fn_backoff_strategy_t poilcy;
    char **retry_on;   /* condition to re-run job, e.g, 5xx error */
    char *dead_letter; /* Internal: Seperate queue for failed messages */
    /* Internal: Execute the function a certain number of times within a time window */
    struct {
        int count;
        struct aura_time_window window;
    } wind_exec;
};

/* ---------- TRIGGERS ---------- */
/* Http trigger structure */
struct aura_fn_http_trigger {
    const struct aura_fn_http_method *http_method;
    struct aura_iovec path;
    const char *auth;
};

/* Crons trigger structure */
struct aura_fn_cron_trigger {
    const char *cron_schedule;
    uint32_t jitter_seconds; /* A random delay in seconds to add to the cron schedule to prevent stampeding */
    const struct aura_fn_cron_misfire_policy *misfire_policy;
    struct aura_fn_retry retry;
};

/* ---------- PROFILES ---------- */
enum {
    LATENCY_OPTIMIZED,
    THROUGHPUT_OPTIMIZED
};

/*
profile: latency-optimized
placement:
  warm_pool: { min_ready_workers: 2, prewarm_on_deploy: true, prewarm_on_spike: true }
resources:
  cpu_quota_ms_per_sec: 120
  cpu_burst_credits: 300
  memory: { soft: 256MiB, hard: 384MiB, oom_policy: throttle }
codegen:
  jit: { tiered: true, optimize_after_calls: 500, code_cache_limit: 64MiB, publish_batch_ms: 10 }
networking:
  connection_pool: { http2: true, idle_ttl: 15s, max_per_origin: 64 }
observability:
  tracing_sample: 0.1
  tail_sampling_target_p99_ms: 120
reliability:
  retries: { policy: exponential, attempts: 4, base: 150ms, jitter: full, retry_on: ["5xx","connect_timeout"] }
*/

/*
profile: throughput-optimized
placement:
  warm_pool: { min_ready_workers: 0, prewarm_on_deploy: false, prewarm_on_spike: true }
resources:
  cpu_quota_ms_per_sec: 80
  cpu_burst_credits: 800
  memory: { soft: 384MiB, hard: 512MiB, oom_policy: kill }
codegen:
  jit: { tiered: true, optimize_after_calls: 2000, code_cache_limit: 128MiB, publish_batch_ms: 25 }
networking:
  connection_pool: { http2: true, idle_ttl: 45s, max_per_origin: 256 }
observability:
  tracing_sample: 0.02
  tail_sampling_target_p99_ms: 250
reliability:
  retries: { policy: exponential, attempts: 2, base: 300ms, jitter: half, retry_on: ["5xx"] }
*/

/* Function meta structure */
struct aura_fn_meta {
    const char *name;
    const char *description;
    uint64_t fn_id;
    const char *version;
    const char *prev_version;
    const char *host;
    const char *entry_point;
    struct aura_fn_http_trigger http_trigger;
    struct aura_fn_cron_trigger cron_trigger;
    struct aura_fn_resources fn_resources;
    struct {
        struct aura_fn_ingress inbound;
        struct aura_fn_egress outbound;
    } networking;
    // storage
    // success_criteria
};

/* Function config structure */
struct aura_fn_config {
    struct aura_iovec *envs;
    size_t env_cnt;
    struct aura_fn_concurrency fn_concurrency;
    struct aura_fn_observability fn_observability;
    // placement
    // deploy
    // timeout
    /**
     * Wait for publish batch milliseconds batching work
     * before passing it over to a function.
     */
    unsigned publish_batch_ms;
};

/** Function stat structure */
struct aura_fn_stat {
    uint64_t invocations;
    uint64_t failures;
    uint64_t latency_ns;
    uint64_t exec_ns;
    uint64_t cold_starts;
    uint64_t last_execution;
};

/**
 * Function stat wrapper structure
 * Used when loading top k busy functions
 * in server
 */
struct aura_fn_stat_wrapper {
    struct aura_fn_stat *fn_stat;
    struct aura_fn_tag *fn_tag;
    struct aura_heap_ent hp_ent;
};

enum {
    A_FN_UNLOADED,
    A_FN_LOADED,
    A_FN_LOADING,
};

/* Fn tag trigger structure */
struct fn_tag_trigger {
    union {
        struct {
            uint8_t method;
            char *path;
        } http_trigger;
        struct {
            char schedule[8];
        } cron_trigger;
    };
    uint8_t trigger;
} __attribute__((packed));

struct aura_fn_triggers {
    struct fn_tag_trigger entries[8]; /* Function triggers */
    uint8_t cnt;                      /* Trigger count */
    uint8_t cap;
};

/**
 * Function structure used in function list structure.
 * It would be nice to be able to represent functions
 * without having to load the massive full function
 * representation.
 */
struct aura_fn_tag {
    uint8_t fn_name[A_FN_NAME_MAX_LEN];       /* Function name */
    uint8_t fn_version[A_FN_VERSION_MAX_LEN]; /* Function version */
    uint64_t fn_id;                           /* Function ID */
    uint64_t timestamp_ms;                    /* Deployment time */
    struct aura_fn_triggers fn_triggers;      /* Fn triggers loaded on demand and not saved as part of fn_tag */
    bool http;                                /* If function is http triggered, use by the server  */
};

/** System functions structure */
struct aura_fn_list {
    size_t func_cnt;
    struct aura_fn_tag *func_tags;
};

/* Function registry entry */
struct aura_fn_registry_ent {
    struct aura_fn_tag fn_tag;
    struct aura_fn *fn;
    struct aura_fn_queue fn_queue;
    uint8_t load_state;
};

/* Function registry structure */
struct aura_fn_registry {
    struct aura_fn_registry_ent entries[A_FN_MAX_REGISTRY_CNT];
    struct aura_rh_map hashmap; /* Quick fn lookup */
    uint64_t cnt;
};

/** Function state */
struct aura_fn_state {
    bool is_active; /* Fn can be invoked */
};

/**
 * Function Complete structure (contains everything about a fn)
 */
struct aura_fn {
    struct aura_fn_meta meta;
    struct aura_fn_config config;
    struct aura_fn_stat stats;
    struct aura_fn_state state;
    uint64_t fn_code_len;
    void *fn_code;
    uint8_t backend;
    /* LRU cache entry */
    struct aura_lru_entry lc_entry;
};

struct aura_fn_tls_version {
    const char *str;
    aura_tls_version_t value;
};

/* Fn event structure */
struct aura_fn_evt {
    uint32_t state;
    int error_code;
    size_t msg_len;
    char msg[4096];
    char *_msg;
};

/* Fn OP states */
typedef enum {
    A_FN_OP_STATE_START = 1,
    A_FN_OP_STATE_RUNNING,
    A_FN_OP_STATE_CONFIG_VALIDATE,
    A_FN_OP_STATE_PETITE, /* A small representation for a fn containing only name and version */
    A_FN_OP_STATE_TAG,    /* A small representation for a fn containing only name and version */
    A_FN_OP_STATE_META,
    A_FN_OP_STATE_CONFIG,
    A_FN_OP_STATE_CODE,
    A_FN_OP_STATE_STAT,
    A_FN_OP_STATE_FN_STATE,
    A_FN_OP_STATE_FN_LIST_UPDATE,
    A_FN_OP_STATE_DONE,
    A_FN_OP_STATE_FAILED
} aura_fn_op_state;

/* Function errors */
typedef enum {
    A_FN_ERROR_NONE,
    A_FN_ERROR_GENERIC,
    A_FN_ERROR_CONFIG,
    A_FN_ERROR_FN_CODE,
    A_FN_ERROR_DUPLICATE,
    A_FN_ERROR_NOT_EXIST
} aura_fn_error;

/** DEPLOY STUFF */
typedef enum {
    DEPLOYMENT_STABLE,
    DEPLOYMENT_CANARY,
    DEPLOYMENT_ROLLBACK_PENDING,
    DEPLOYMENT_ROLLED_BACK
} deployment_state_t;

struct aura_fn_deployment_stat {
    uint64_t deployment_time;
    double error_rate_threshold;
    double latency_increase_threshold;
    double throughput_drop_threshold;
    double current_error_rate;
    double baseline_error_rate;
    double current_p95_latency;
    double baseline_p95_latency;

    deployment_state_t state;
    uint64_t last_evaluation_time;
};

typedef void (*aura_rollback_cb)(uint64_t fn_id, const char *version, double error_rate, const char *reason);

struct aura_rollback_detector {
    struct aura_fn_deployment_stat *deployment;
    int max_attempts;
    aura_rollback_cb rb_callback;

    // Aggregation window
    uint64_t short_window_ms;  // immediate detection, provided by user
    uint64_t medium_window_ms; // trend analysis (maybe 5 mins)
    uint64_t long_window_ms;   // 1 hour for baseline comparison
};

/** Get the numeric value of the method str */
static inline const struct aura_fn_http_method *aura_fn_http_method_get(const char *str) {
    int val;

    if (aura_scan_str(str, "%u" SCNu32, &val) < 0)
        return NULL;

    switch (val) {
    case GET:
        return &http_methods[GET - 1];
    case POST:
        return &http_methods[POST - 1];
    case PUT:
        return &http_methods[PUT - 1];
    case PATCH:
        return &http_methods[PATCH - 1];
    case DELETE:
        return &http_methods[DELETE - 1];
    case HEAD:
        return &http_methods[HEAD - 1];
    default:
        return NULL;
    }
}

/** Get the numeric value of the policy str */
static inline const struct aura_fn_cron_misfire_policy *aura_fn_cron_misfire_policy_get(const char *str) {
    int val;

    if (aura_scan_str(str, "%u" SCNu32, &val) < 0)
        return NULL;

    switch (val) {
    case FIRE_NOW:
        return &misfire_policies[FIRE_NOW - 1];
    case IGNORE:
        return &misfire_policies[IGNORE - 1];
    case RESCHEDULE:
        return &misfire_policies[RESCHEDULE - 1];
    default:
        return NULL;
    }
}

static inline const struct aura_fn_oom_policy *aura_fn_oom_policy_get(const char *str) {
    int val;

    if (aura_scan_str(str, "%u" SCNu32, &val) < 0)
        return NULL;

    switch (val) {
    case KILL:
        return &oom_policies[KILL - 1];
    case SNAPSHOT_THEN_KILL:
        return &oom_policies[SNAPSHOT_THEN_KILL - 1];
    case THROTTLE:
        return &oom_policies[THROTTLE - 1];
    default:
        return NULL;
    }
}

/**
 * copy function transfering ownership of
 * internal fields over to the cache slot
 * represented by lru_entry.
 */
// static inline void aura_fn_cache_load(struct aura_lru_entry *e, struct aura_fn *fn) {
//     uint64_t fn_size = offsetof(struct aura_fn, lc_entry);
//     void *slot = aura_lru_cache_entry(e, struct aura_fn, lc_entry);
//     /**
//      * lru entry is the last member of
//      * the fn struct. fn_size should there
//      * represent the length excluding the last
//      * member "lc_entry". We only copy the fn part.
//      */
//     memcpy(slot, fn, fn_size);

//     /**
//      * zero out the fn since we just transfer fields over.
//      * This was deleting the function does invalidate the fields.
//      */
//     memset(fn, 0, sizeof(*fn));
// }

/* Create function backing cache */
static inline struct aura_slab_cache *aura_fn_slab_cache_create(struct aura_mem_ctx *mc) {
    return aura_slab_cache_create(
      mc,
      A_FN_SLAB_CACHE_ID,
      "function cache",
      sizeof(struct aura_fn),
      NULL,
      0);
}

/* Dump fn event structure */
static inline void aura_fn_evt_response_dump(struct aura_fn_evt *evt, bool daemon) {
    app_debug(daemon, 0, "AURA FN EVT RESPONSE");
    app_debug(daemon, 0, "    State: %u", evt->state);
    app_debug(daemon, 0, "    Error: %d", evt->error_code);
    app_debug(daemon, 0, "    Msg Len: %u", evt->msg_len);
    if (evt->msg_len > 0)
        app_debug(daemon, 0, "    Message: %p", evt->_msg);
}

/**
 * Given a function representation string passed from
 * cli. Extract the fn name and version.
 */
static inline void aura_fn_get_name_and_version(struct iovec *fn, char *fn_name,
                                                uint64_t func_len, char *fn_version,
                                                uint64_t func_vlen) {
    memset(fn_name, 0, func_len);
    memset(fn_version, 0, func_vlen);

    /* assume no version was provided */
    func_len = fn->iov_len;

    char *sep = strchr(fn->iov_base, ':');
    if (sep) {
        /**
         * Function key provided as <fn_name>:<fn_version>
         * We therefore copy the function version
         * found after the sep(:).
         */
        *sep = '\0';
        func_vlen = ((char *)fn->iov_base + fn->iov_len) - (sep + 1);
        memcpy(fn_version, sep + 1, func_vlen);

        /* account for version and separator */
        func_len -= func_vlen - 1;
    }

    memcpy(fn_name, fn->iov_base, func_len);
}

/* Parse function meta data */
int aura_fn_meta_parse(void *meta, struct aura_fn_meta *fn_meta);

/* Parse function config */
int aura_fn_config_parse(void *config, struct aura_fn_config *fn_config);

/* Destroy funtion meta data */
void aura_fn_meta_destroy(const struct aura_fn_meta *fn_meta);

/* Destroy function config */
void aura_fn_config_destroy(struct aura_fn_config *fn_config);

/* Destroy function resource structure */
void aura_fn_resources_destroy(const struct aura_fn_resources *resources);

/* Destroy function http trigger structure */
void aura_fn_http_trigger_destroy(const struct aura_fn_http_trigger *http_trigger);

/* Destroy function cron trigger structure */
void aura_fn_cron_trigger_destroy(const struct aura_fn_cron_trigger *cron_trigger);

/* Destroy function networking structure */
void aura_fn_networking_destroy(const void *networking);

/**
 * Get 'tiny' function meta data from
 * list of functions
 */
struct aura_fn_tag *aura_fn_tag_fetch(AURA_DBHANDLE db, struct aura_mem_ctx *mc,
                                      const char *fn_name, const char *fn_version,
                                      int *error);

/** Get the list of functions deployed in the system */
struct aura_fn_list *aura_fn_list_fetch(AURA_DBHANDLE db, int *error);

/** Add a new function to the list of deployed functions */
int aura_fn_list_add_fn(AURA_DBHANDLE db, struct aura_mem_ctx *mc, struct aura_fn_meta *fn_meta);

/** Brokered fetch for the list of deployed functions */
struct aura_fn_list *aura_fn_list_fetch_brokered(struct aura_mem_ctx *mc, int dmn_sock_fd, int *error);

/** Remove a function from the list of deployed functions */
int aura_fn_list_delete(AURA_DBHANDLE db, struct aura_mem_ctx *mc,
                        char *fn_name, char *fn_version);

/* Get function meta */
struct aura_iovec aura_fn_meta_fetch(AURA_DBHANDLE db, char *fn_name, char *fn_version);

/* Get function config */
struct aura_iovec aura_fn_config_fetch(AURA_DBHANDLE db, char *fn_name, char *fn_version);

/* Get function code */
struct aura_iovec aura_fn_code_fetch(AURA_DBHANDLE db, char *fn_name, char *fn_version);

/* Get function state*/
struct aura_iovec aura_fn_state_fetch(AURA_DBHANDLE db, char *fn_name, char *fn_version);

/* Get a function's complete structure */
struct aura_fn *aura_fn_load(AURA_DBHANDLE db, struct aura_mem_ctx *mc, char *fn_name, char *fn_version);

/* Initialize function registry */
int aura_fn_registry_init(struct aura_fn_registry *r, struct aura_mem_ctx *mc, uint32_t max_size);

/* Initialize fn cache */
int aura_fn_cache_init(struct aura_lru_cache *cache, struct aura_mem_ctx *mc);

/* Load function registry */
struct aura_fn_registry_ent *aura_fn_load_fn_registry_entry(struct aura_fn_registry *r,
                                                            struct aura_fn_tag *fn_tag);

/* */
struct aura_fn_stat *aura_fn_stat_fetch_brokered(struct aura_mem_ctx *mc, char *fn_name,
                                                 char *fn_version, int dmn_fd);

/* */
// struct aura_fn *aura_fn_load_brokered(struct aura_mem_ctx *mc, char *fn_name, char *fn_version, int sock_fd);
int aura_fn_load_brokered(struct aura_mem_ctx *mc, struct aura_fn *fn,
                          char *fn_name, char *fn_version, int sock_fd);

/** Fetch function stats */
struct aura_fn_stat *aura_fn_stat_fetch(AURA_DBHANDLE db, char *fn_name, char *fn_version);

/* Compare function stats */
int aura_fn_stat_compare(struct aura_heap_ent *s1, struct aura_heap_ent *s2);

/* Initialize function queue */
int aura_fn_queue_init(struct aura_fn_queue *q, struct aura_worker_pool *glob_pool);

/* Destroy function structure */
void aura_fn_destroy(struct aura_fn *fn);

/* Destroy a function tag */
void aura_fn_tag_destroy(struct aura_fn_tag *fn_tag);

int aura_fn_fetch_trigger(AURA_DBHANDLE db, struct aura_fn_triggers *fn_triggers,
                          const char *name, const char *version, int *error);

int aura_fn_fetch_trigger_brokered(struct aura_mem_ctx *mc, struct aura_fn_triggers *fn_triggers,
                                   const char *name, const char *version, int *error, int dmn_sock_fd);

/* Dump fn metadata */
void aura_fn_meta_dump(struct aura_fn_meta *fn_meta);

/* Dump function config */
void aura_fn_config_dump(struct aura_fn_config *fn_conf);

/* Dump function stats */
void aura_fn_stat_dump(struct aura_fn_stat *stats);

/* Dunp function tag */
void aura_fn_dump_fn_tag(struct aura_fn_tag *tag);
#endif