#ifndef AURA_SRV_OPTIMIZATION
#define AURA_SRV_OPTIMIZATION

#include "memory_lib.h"
#include "slab_lib.h"

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

#endif