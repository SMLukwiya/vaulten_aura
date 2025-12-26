#ifndef AURA_DMN_FUNCTION_H
#define AURA_DMN_FUNCTION_H

#include "blobber_lib.h"
#include "yaml_lib.h"

#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>

enum a_fn_node_idx {
    A_IDX_FN_NONE,
    A_IDX_FN_NAME,
    A_IDX_FN_DESCRIPTION,
    A_IDX_FN_VERSION,
    A_IDX_FN_HOST,
    A_IDX_FN_ENTRY_POINT,
    A_IDX_FN_ENV
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

#define MAX_TRIGGERS 3
#define MAX_TLS_VERSIONS 2
#define MAX_CIRCUIT_BREAKER_TRIGGERS 3

#define CREATE_LOOKUP_MAP(enum_type, enum_name) \
    struct aura_##enum_type##_map {             \
        const char *str;                        \
        enum_type enum_name;                    \
    }

typedef enum {
    JIT,
    NATIVE,
    WASM
} aura_runtime_t;

typedef enum {
    HTTP,
    CRON,
    QUEUE
} aura_trigger_t;

typedef enum {
    TCP,
    UDP
} aura_protocol_t;

typedef enum {
    TLS_1_2,
    TLS_1_3
} aura_tls_version_t;

typedef enum {
    GET,
    POST,
    PUT,
    PATCH,
    DELETE,
    HEAD
} aura_http_method_t;

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
} aura_log_level_t;

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
} aura_cron_misfire_policy_t;

struct aura_queue_trigger {
    const char *topic;             /* The name of the managed queue to consume messages from. */
    u_int32_t per_key_concurrency; /* Internal */
};

struct aura_concurrency {
    unsigned int max_instances; /* The max number of concurrent instances for this function. */
    bool pre_warm_on_deploy;    /* create function ready instance(s) on deploy */
    bool background_tasks;      /* Enables the API for this function to submit background tasks. */
    u_int32_t delay;            /* Time between new instance spin up until max instances */
};

typedef enum {
    KILL,
    SNAPSHOT_THEN_KILL,
    THROTTLE
} aura_oom_policy_t;

struct aura_resources {
    u_int32_t memory_limit_mb_soft;        /* Soft memory limit MBs */
    u_int32_t memory_limit_mb_hard;        /* Hard memory limit MBs */
    u_int32_t cpu_shares;                  /* Relative CPU share compared to other functions. */
    u_int32_t timeout;                     /* The max execution time for a single invocation of the function in ms. */
    u_int32_t cpu_burst_credit;            /* Internal: function can exceed their cpu limits based on good behaviour */
    u_int32_t io_net_egress_bytes_per_sec; /* Internal: Amount of data leaving the network because of this function */
    u_int32_t socket_max;                  /* Internal: */
    aura_oom_policy_t oom_pol;
};

/**
 * Sandbox settings: Internal
 */
struct aura_environment {
    struct {
        u_int32_t max_instances; /* Instantly available number of sandbox instances. */
        bool prewarm_on_deploy;
    } aura_worker_pool;
};

/**
 * NETWORK CONNECTION
 */
struct aura_ingress {
    char **ip_whitelist; /* A list of IP addresses or CIDR blocks allowed to invoke the function. */
    size_t whitelsit_len;
    aura_network_policy_t policy; /* The default inbound network policy. */
};

struct aura_egress_connection {
    const char *host;
    u_int16_t port;
    aura_protocol_t protocol;
    aura_tls_version_t prot_version;
    bool secure;
    u_int32_t idle_ttl;
    u_int32_t max_per_origin;
};

struct aura_egress {
    struct aura_egress_connection **hosts; /* A list of IP addresses or CIDR blocks allowed to invoke the function. */
    size_t whitelist_len;
    aura_network_policy_t policy; /* The default outbound network policy. */
};

/**
 * Managed identity and authorization for calling other functions.
 * INTERNAL
 */
struct aura_inter_service_auth {
    char **allowed_services; /* A list of other functions that this function is authorized to call. */
};

/**
 * STORAGE
 */
/**
 * Enables automatic replication of a static asset bucket to the edge node.
 */
struct aura_static_assets {
    const char *bucket_name; /* The name of the read-only bucket to replicate locally. */
};

struct aura_persistent_volume {
    bool enabled;      /* Enables managed persistent volume to the sandbox. */
    u_int32_t size_mb; /* The size of the persistent volume in megabytes. */
};

/**
 * Managed state and persistent storage options for the function.
 */
struct aura_storage {
    union {
        bool key_value_store; /* Enables a managed key-value store for the function. */
        struct aura_persistent_volume fn_persistent_vol;
        struct aura_static_assets fn_static_assets;
    };
};

/*
 * OBSERVABILITY
 */
/**
 * Controls for logging, tracing, and custom metrics.
 */
typedef enum {
    PII_DEFAULT,
    REDACT_STRICT,
    REDACT_NONE
} aura_log_redact_level_t;

struct aura_logging {
    char *destination;      /* The URL or identifier of the external logging service. */
    aura_log_level_t level; /* The minimum logging level to output. */
    aura_log_redact_level_t log_redact;
};

struct aura_tracing {
    bool enabled;    /* Distributed tracing for the function. */
    int sample_rate; /* The rate at which to sample traces (0.0 to 1.0). */
    /**
     * INTERNAL
     * We should trace all requests that exceed this latency,
     * while only sampling the 'sample_rate' requests below it.
     */
    u_int32_t tail_sampling_target_ms;
};

struct aura_observability {
    struct aura_logging fn_logging;
    struct aura_tracing fn_tracing;
    bool custom_metrics;
};

/**
 * DEPLOYMENT AND PLACEMENT
 */
struct aura_placement {
    const char **prefer_regions; /* list of prefered regions */
    const char **avoid_regions;  /* list of avoid regions */
};

typedef enum {
    CANARY,
    BLUE_GREEN,
    ROLLING
} aura_deployment_strategy_t;

typedef enum {
    BLUE,
    GREEN
} aura_blue_green_t;

struct aura_deployment {
    aura_deployment_strategy_t strategy;
    union {
        u_int8_t percentage;
        u_int32_t batch;
        aura_blue_green_t primary;
    };
};

struct aura_success_rules {
    u_int32_t min_availability;
    u_int32_t p95_latency_lt;
    u_int8_t error_rate;
};

struct aura_success_ctx {
    const char *health_check; /** @todo: = */
    struct aura_success_rules rules;
    u_int32_t rollback_after;
};

struct aura_fleet {
    const char *name;
    struct aura_deployment deploy_strategy;
};

/* CODEGEN */
typedef enum {
    GCC,
    CLANG
} aura_supported_compiler_t;

struct aura_codegen {
    struct {
        /**
         * When false, ignores optimize_after_calls(see below),
         * we compile with max optimization upfront. If not take optimize_after_calls
         * into account and perform optimization as specified.
         */
        bool tiered;
        /**
         * Function must produce the exact same output for the same
         * input on every run. Machine state should not matter.
         * Used for event sourcing, caching and possibly replay
         */
        bool deterministic;
        /**
         * Use multiple compilation tiers, possibly fast unoptimized initial
         * run, then trigger aggressive compilation after the function has
         * executed optimize_after_calls times. 0 would mean compile aggressive
         * upfront. User could supply their max valid optimization flag for choosen compiler.
         * Binaries are cached by default. So we should not suffer
         * delays on subsequent runs
         */
        int optimize_after_calls;
        /**
         * User can pass compiler option with flags, GCC, CLANG from config,
         * javascript folks currently have no option aside from v8,
         * we shall surely sort you in the near future!.
         */
        aura_supported_compiler_t compiler;
        const char *compiler_flags; /* see a better way to respresent this */
    } jit;
};

/**
 * DURABILIBILITY
 */
/* Durability should be strictly optin */ // this plays in with persistent volume/key-value storage
struct aura_durability {
    /**
     * A unique identifier for a logical "actor" or state entity
     * We could use this to route all invocations for a specific
     * actor to the same fn instance.
     */
    char *actor;
    /**
     * We can queue up this many messages for a single actor
     * in our key value store before we start rejecting new messages.
     * We can degrade gracefully and signal upstream services.
     */
    u_int32_t mailbox_limit;
    /**
     * We serialize and persist the actor's in-memory
     * state at this interval in milliseconds.
     */
    u_int32_t snapshot_every_ms;
};

/**
 * RELIABILITY
 */
struct aura_time_window {
    time_t start;
    time_t end;
};

typedef enum {
    BACKOFF_NONE,
    BACKOFF_FIXED,
    BACKOFF_EXPONENTIAL
} aura_backoff_t;

struct aura_retry {
    u_int32_t attempts;
    aura_backoff_t poilcy;
    char **retry_on;   /* condition to re-run job, e.g, 5xx error */
    char *dead_letter; /* Internal: Seperate queue for failed messages */
    /* Internal: Execute the function a certain number of times within a time window */
    struct {
        int count;
        struct aura_time_window window;
    } wind_exec;
};

/**
 * TRIGGERS
 */
struct aura_http_trigger {
    const char *url_path;
    aura_http_method_t http_method;
    const char *auth;
};

struct aura_cron_trigger {
    const char *cron_schedule;
    u_int32_t jitter_seconds; /* A random delay in seconds to add to the cron schedule to prevent stampeding */
    u_int32_t max_concurrent; /* Internal: Run 1 or multiple instances of job in parallel */
    aura_cron_misfire_policy_t misfire_policy;
    struct aura_retry retry;
};

/**
 * A function should be able to specify a couple of
 * circuit breakers (if it needs to), this would specify hints
 * to the system when to perhaps report an error related to the
 * entities involved, an example would be when talking an an
 * external API, then the API goes down,
 * we wouldn't want to queue up message very long!
 */
struct aura_circuit_breaker_entity {
    const char *name; /* unique identifier for a specific circuit */
    /**
     * This is the percentage of recent failures that
     * should trip the circuit breaker.
     * Once we hit this threshold, we relax!
     */
    int failure_ratio;
    struct aura_time_window window; /* duration taken into consideration when calculating failure_ratio */
    /**
     * After this amount of time, we have lifted the original ban from
     * the external entity that caused the failure, we then start
     * sending a trickle of test requests to see if the entity is healthy.
     * If it's healthy, we transition to full open to send whatever was left in the queue.
     * If not, if we should trigger a red-alert and report the victim entity to the user.
     * Note that we do not report the victim entity on the first sign of trouble,
     * because nobody likes a snitch!!
     * We assume the victim entity has enough honour to report it's own failure first!!.
     */
    int half_open_after;
};

struct aura_circuit_breaker {
    struct aura_circuit_breaker_entity circuit_breakers[MAX_CIRCUIT_BREAKER_TRIGGERS];
};

/**
 * PROFILES
 */
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

struct aura_function {
    u_int64_t fn_id;
    const char *name;
    const char *description;
    const char *version;
    const char *prev_version;
    aura_runtime_t runtime;
    const char *entry_point;
    struct {
    } env;
    struct aura_http_trigger http_trigger;
    struct aura_cron_trigger cron_trigger;
    struct aura_queue_trigger queue_trigger;
    u_int64_t last_execution; /* time since last execution */
    struct aura_resources fn_resources;
    struct aura_concurrency fn_concurrency;
    struct {
        struct aura_ingress inbound;
        struct aura_egress outbound;
    } networking;
    struct aura_observability fn_observability;
    struct aura_environment fn_envt;
    /**
     * In the case that a function processes event streams,
     * we can decide to wait for this maximum number of milliseconds
     * and collect a batch of events before passing it over to a function.
     */
    unsigned publish_batch_ms;
}; /* packed aligned 64 perhaps */

struct generic_map {
    const char *str;
    int value;
};

struct aura_http_method_t_map {
    const char *str;
    aura_http_method_t value;
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
    aura_log_level_t value;
};

struct aura_oom_policy_t_map {
    const char *str;
    aura_oom_policy_t value;
};

struct aura_log_redact_level_t_map {
    const char *str;
    aura_log_redact_level_t value;
};

struct aura_deployment_strategy_t_map {
    const char *str;
    aura_deployment_strategy_t value;
};

struct aura_blue_green_t_map {
    const char *str;
    aura_blue_green_t value;
};

struct aura_backoff_t_map {
    const char *str;
    aura_backoff_t value;
};

struct aura_cron_misfire_policy_t_map {
    const char *str;
    aura_cron_misfire_policy_t value;
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
struct aura_fn_deployment {
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
    struct aura_fn_deployment *deployment;
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