#ifndef AURA_SRV_OPTIMIZER_H
#define AURA_SRV_OPTIMIZER_H

#include "mem.h"
#include "slab.h"
#include "sliding_buf.h"
#include "utils_lib.h"

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#define A_ETHERNET_MTU 1500
#define A_TCP_V4_HEADER_SIZE 40
#define A_TCP_V6_HEADER_SIZE 60
#define A_TLS_HEADER_SIZE 5
#define A_TLS_MAX_PLAINTEXT 16384U
#define A_TLS_IV_SIZE 16
#define A_TLS_TAG_SIZE 16
#define A_TLS_RECORD_OVERHEAD (A_TLS_HEADER_SIZE + A_TLS_IV_SIZE + A_TLS_TAG_SIZE)

/* TLS record config structure */
struct aura_tls_record_config {
    uint16_t tcp_mss;
    uint16_t ipv6_mss;

    enum {
        A_TLS_SIZE_AGGRESSIVE,   /* Full frames (Max payload) */
        A_TLS_SIZE_CONSERVATIVE, /* MTU-sized */
        A_TLS_SIZE_DYNAMIC,      /* Adaptive based on RTT/loss */
        A_TLS_SIZE_STREAMING     /* Optimized for streaming data */
    } strategy;

    uint16_t optimal_plaintext;    /* Plain text per record */
    uint16_t optimal_cipher_text;  /* Cipher text (plain text + record overhead) */
    uint16_t max_records_per_call; /* For vectorized ops */

    uint32_t rtt_us; /* Smoothed RTT */
    float loss_rate; /* Estimated loss rate */
    bool is_ipv6;    /* connection is IPV6 */
    bool is_mobile;  /* Mobile hint */
};

/* TLS record structure */
struct aura_tls_record {
    struct aura_sliding_buf ciphertext;
    struct aura_sliding_buf plaintext;

    uint8_t priority;
    bool needs_immediate_ack;
    uint64_t enqueued_at;

    struct aura_list_head t_list;
};

/* TLS batch record structure */
struct aura_tls_record_batch {
    struct aura_list_head record_list;
    size_t cnt;
    size_t total_plaintext;
    size_t total_ciphertext;

    struct iovec *iovecs;
    size_t iovec_cnt;
    /**
     * Indicates if this record batch is ready for vectorized io,
     * this means batch.iovecs is ready and we can use writev
     */
    bool iov_ready;
};

/* === */

#define A_INTEGRAL_LIMIT 1000

/* Server optimizer struct */
struct aura_srv_optimizer {
    int min_accept;
    int max_accept;
    int conc;
    int conc_max;
    int conc_min;

    float error_integral;

    float alpha; /* EMWA smoothing factor */
    float kp;    /* Proportional gain */
    float ki;    /* Integral gain */
    float kf;

    double prev_tp;
    double prev_latency;
    int prev_conc;

    float tp_threshold;
    float tp_drop_threshold;
    float latency_threshold;
    uint8_t min_consecutive_cnt;
    uint8_t knee_counter;

    bool knee_detected;
    int knee_concurrency;

    double target_latency_us;
    double ewma_latency;

    uint64_t last_timestamp_us; /* Last run of optmizer */

    uint32_t current_accept_budget;

    float knee_margin_ratio;
    uint8_t knee_holdoff; /* Hold time after knee detection */
    uint8_t knee_holdoff_counter;
    float min_delta_conc;    /* Minimum change to compute slopes */
    float tp_slope_ema;      /* Filtered slope for noise reduction */
    float latency_slope_ema; /* Filtered slope for noise reduction */
    float slope_alpha;       /* EWMA factor for slope */
    float error_deadzone;    /* Limit concurrency hunt near steady state */
};

void aura_srv_opt_init(struct aura_srv_optimizer *opt);

void aura_srv_opt_req_complete(struct aura_srv_optimizer *opt, double latenc_ms);

void aura_srv_opt_update(struct aura_srv_optimizer *opt, uint64_t now, double throughput, uint32_t inflight);

int64_t aura_srv_opt_get_candidate_epoll_timeout(struct aura_srv_optimizer *opt);

uint64_t aura_srv_opt_get_accept_budget(struct aura_srv_optimizer *opt, uint64_t inflight);

#endif