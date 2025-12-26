#ifndef AURA_FUNCTION_LIB_H
#define AURA_FUNCTION_LIB_H

#include "blobber_lib.h"
#include "radix_lib.h"
#include "time_lib.h"
#include "types_lib.h"

#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>

#define MAX_CIRCUIT_BREAKER_TRIGGERS 3

enum a_fn_node_idx {
    A_IDX_FN_NONE,
    A_IDX_FN_NAME,
    A_IDX_FN_DESCRIPTION,
    A_IDX_FN_VERSION,
    A_IDX_FN_HOST,
    A_IDX_FN_ENTRY_POINT,
    A_IDX_FN_ENV,
    A_IDX_FN_TRIGGERS,
    A_IDX_FN_HTTP_TRIGGER,
    A_IDX_FN_MIN_INSTANCES,
    A_IDX_FN_MAX_INSTANCES,

};

/*--------------*/
struct aura_yml_fn_data_ctx {
    int dir_fd; /* function directory fd */
    bool seen_aura_version;
    bool extract;
    aura_rax_tree_t *parse_tree;
    st_aura_b_builder builder;
    struct aura_yml_node *node_arr;
    uint32_t node_cap;
    uint32_t node_cnt;
    uint32_t node_len;
};

typedef enum {
    JIT,
    NATIVE,
    WASM
} aura_runtime_t;

typedef enum {
    A_TRIGGER_HTTP,
    A_TRIGGER_CRON,
    A_TRIGGER_QUEUE
} aura_trigger_t;

typedef enum {
    TCP,
    UDP
} aura_protocol_t;

typedef enum {
    TLS_1_3
} aura_tls_version_t;

typedef enum {
    GET,
    POST,
    PUT,
    PATCH,
    DELETE,
    HEAD
} aura_fn_http_method_t;

typedef enum {
    ALLOW_ALL,
    DENY_ALL,
    WHITELIST
} aura_network_policy_t;

typedef enum {
    TRACE,
    INFO,
    DEBUG,
    WARN,
    ERROR
} aura_fn_log_level_t;

typedef enum {
    NONE,
    JWT,
    MTLS,
    CUSTOM
} aura_auth_t;

typedef enum {
    FIRE_NOW,  /* Execute missed jobs immediately when possible */
    IGNORE,    /* Drop missed execution and wait for next schedule */
    RESCHEDULE /* Run the job at the next possible time while maintaining original schedule */
} aura_fn_cron_misfire_policy_t;

struct aura_concurrency {
    uint32_t min_instances;  /* Min concurrent instances to be alive at all time */
    uint32_t max_instances;  /* The max number of concurrent instances for this function. */
    u_int32_t delay;         /* Time between new instance spin up until max instances */
    bool pre_warm_on_deploy; /* create function ready instance(s) on deploy */
    bool background_tasks;   /* Enables the API for this function to submit background tasks. */
};

typedef enum {
    KILL,
    SNAPSHOT_THEN_KILL,
    THROTTLE
} aura_fn_oom_policy_t;

struct aura_fn_resources {
    u_int32_t memory_limit_mb_soft;        /* Soft memory limit MBs */
    u_int32_t memory_limit_mb_hard;        /* Hard memory limit MBs */
    u_int32_t cpu_shares;                  /* Relative CPU share compared to other functions. */
    u_int32_t timeout;                     /* The max execution time for a single invocation of the function in ms. */
    u_int32_t cpu_burst_credit;            /* Internal: function can exceed their cpu limits based on good behaviour */
    u_int32_t io_net_egress_bytes_per_sec; /* Internal: Amount of data leaving the network because of this function */
    u_int32_t socket_max;                  /* Internal: */
    aura_fn_oom_policy_t oom_pol;
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
    u_int16_t port;
    aura_protocol_t protocol;
    aura_tls_version_t prot_version;
    bool secure;
    u_int32_t idle_ttl;
    u_int32_t max_per_origin;
};

struct aura_fn_egress {
    struct aura_fn_egress_connection **hosts; /* A list of IP addresses or CIDR blocks allowed to invoke the function. */
    size_t whitelist_len;
    aura_network_policy_t policy; /* The default outbound network policy. */
};

/* ---------- OBSERVABILITY ---------- */
/**
 * Controls for logging, tracing, and custom metrics.
 */
typedef enum {
    PII_DEFAULT,
    REDACT_STRICT,
    REDACT_NONE
} aura_fn_log_redact_level_t;

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
    u_int32_t tail_sampling_target_ms;
};

struct aura_fn_observability {
    struct aura_fn_logging fn_logging;
    struct aura_fn_tracing fn_tracing;
    bool custom_metrics;
};

typedef enum {
    CANARY,
    BLUE_GREEN,
    ROLLING
} aura_fn_deployment_strategy_t;

typedef enum {
    BLUE,
    GREEN
} aura_fn_blue_green_strategy_t;

struct aura_fn_deployment {
    aura_fn_deployment_strategy_t strategy;
    union {
        u_int8_t percentage;
        u_int32_t batch;
        aura_fn_blue_green_strategy_t primary;
    };
};

struct aura_fn_success_rules {
    u_int32_t min_availability;
    u_int32_t p95_latency_lt;
    u_int8_t error_rate;
};

struct aura_fn_success_ctx {
    const char *health_check; /** @todo: = */
    struct aura_fn_success_rules rules;
    u_int32_t rollback_after;
};

/* ---------- RELIABILITY ---------- */
typedef enum {
    BACKOFF_NONE,
    BACKOFF_FIXED,
    BACKOFF_EXPONENTIAL
} aura_fn_backoff_strategy_t;

struct aura_fn_retry {
    u_int32_t attempts;
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
struct aura_fn_http_trigger {
    aura_fn_http_method_t http_method;
    struct aura_iovec path;
    const char *auth;
};

struct aura_fn_cron_trigger {
    const char *cron_schedule;
    u_int32_t jitter_seconds; /* A random delay in seconds to add to the cron schedule to prevent stampeding */
    u_int32_t max_concurrent; /* Internal: Run 1 or multiple instances of job in parallel */
    aura_fn_cron_misfire_policy_t misfire_policy;
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

struct aura_fn {
    u_int64_t fn_id;
    const char *name;
    const char *description;
    const char *version;
    const char *prev_version;
    // aura_runtime_t runtime;
    const char *entry_point;
    struct aura_iovec *envs;
    struct aura_fn_http_trigger http_trigger;
    struct aura_fn_cron_trigger cron_trigger;
    u_int64_t last_execution; /* time since last execution */
    struct aura_fn_resources fn_resources;
    struct aura_concurrency fn_concurrency;
    struct {
        struct aura_fn_ingress inbound;
        struct aura_fn_egress outbound;
    } networking;
    struct aura_fn_observability fn_observability;
    /**
     * In the case that a function processes event streams,
     * we can decide to wait for this maximum number of milliseconds
     * and collect a batch of events before passing it over to a function.
     */
    unsigned publish_batch_ms;
    void *fn_code;
    uint64_t fn_code_len;
}; /* packed aligned 64 perhaps */

/** @todo: not used */
struct generic_map {
    const char *str;
    int value;
};

struct aura_http_method_t_map {
    const char *str;
    aura_fn_http_method_t value;
};

struct aura_trigger_t_map {
    const char *str;
    aura_trigger_t value;
};

struct aura_network_policy_t_map {
    const char *str;
    aura_network_policy_t value;
};

struct aura_runtime_t_map {
    const char *str;
    aura_runtime_t value;
};

struct aura_protocol_t_map {
    const char *str;
    aura_protocol_t value;
};

struct aura_tls_version_t_map {
    const char *str;
    aura_tls_version_t value;
};

struct aura_log_level_t_map {
    const char *str;
    aura_fn_log_level_t value;
};

struct aura_oom_policy_t_map {
    const char *str;
    aura_fn_oom_policy_t value;
};

struct aura_log_redact_level_t_map {
    const char *str;
    aura_fn_log_redact_level_t value;
};

struct aura_deployment_strategy_t_map {
    const char *str;
    aura_fn_deployment_strategy_t value;
};

struct aura_blue_green_t_map {
    const char *str;
    aura_fn_blue_green_strategy_t value;
};

struct aura_backoff_t_map {
    const char *str;
    aura_fn_backoff_strategy_t value;
};

struct aura_cron_misfire_policy_t_map {
    const char *str;
    aura_fn_cron_misfire_policy_t value;
};

/*************************************************************/
/** DEPLOY STUFF */

typedef enum {
    DEPLOYMENT_STABLE,
    DEPLOYMENT_CANARY,
    DEPLOYMENT_ROLLBACK_PENDING,
    DEPLOYMENT_ROLLED_BACK
} deployment_state_t;

/** @todo: this may be part of the upper function structure */
/** @todo: I could be watching several functions for success deployment */
struct aura_fn_deployment_stat {
    char *function_name;
    char *version;
    uint64_t deployment_time;

    double error_rate_threshold;
    double latency_increase_threshold;
    double throughput_drop_threshold;

    // struct aura_sliding_metrics current_window;
    // struct aura_sliding_metrics baseline_window;

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

struct aura_rollback_detector *rollback_detector_create(aura_rollback_cb cb);
void rollback_detector_add_deployment(struct aura_rollback_detector *rbd, uint64_t fn_id, const char *version /* create a struct to pass error threshold stuff */);
void rollback_detector_record_metrics();
void rollback_detector_evaluate();

#endif