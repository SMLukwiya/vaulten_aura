/**
 * Discrete time simulator for edge-native TWS schedular
 * Models: feedback control, slice allocation, work stealing, numa effects
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define A_SIM_TICKS 10000
#define WARMUP_TICKS 1000
#define MEASUREMENT_WINDOW 100

#define BASE_LATENCY_US 100.0
#define SLO_LATENCY_US 5000.0 /* 5ms */

/* Traffic patterns */
#define NORMAL_RATE 1000.0 /* 1000 reqs/tick */
#define BURST_RATE 5000.0  /* 5x normal */
#define IDLE_RATE 100.0    /* 0.1 normal */

/* Feedback constants */
#define ALPHA 0.2              /* EWMA for drift */
#define BETA 0.2               /* EWMA for pressure */
#define GAMMA 0.1              /* EWMA for latency */
#define TARGET_UTILIZATION 0.8 /* 80% utilization target */

/* Slice parameter */
#define MAX_SLICES_PER_TICK 1000
#define BASE_SLICES_CRITICAL 4
#define BASE_SLICES_LATENCY 3
#define BASE_SLICES_THROUGHPUT 2
#define BASE_SLICES_MAINTENANCE 1

typedef enum {
    REGIME_IDLE = 0,
    REGIME_NORMAL,
    REGIME_BUSY,
    REGIME_CRITICAL,
    REGIME_MAX
} regime_t;

typedef enum {
    WORK_CRITICAL = 0,
    WORK_LATENCY,
    WORK_THROUGHPUT,
    WORK_MAINTENANCE,
    WORK_CLASS_MAX
} work_class_t;

/* Traffic pattern generator */
struct pattern {
    const char *name;
    double (*rate_at)(int tick);
};

/* Pattern 1: square wave burst */
double square_wave_rate(int tick) {
    int phase = (tick / 2000) % 4;
    switch (phase) {
    case 0:
        return NORMAL_RATE;
    case 1:
        return BURST_RATE;
    case 2:
        return NORMAL_RATE;
    case 4:
        return IDLE_RATE;
    default:
        return NORMAL_RATE;
    }
}

/* Pattern 2: Sine wave with increasing frequency */
double sine_wave_rate(int tick) {
    double freq = 0.001 + (tick / 1000000.0);
    return NORMAL_RATE + 3000.0 * sin(2 * M_PI * freq * tick);
}

/* Pattern 3: Step increase(permanent load spike) */
double step_rate(int tick) {
    return tick < 3000 ? NORMAL_RATE : BURST_RATE * 2;
}

/* Pattern 4: Realistic diurnal pattern */
double diurnal_rate(int tick) {
    double day_phase = (tick % 10000) / 10000.0; /* 0-1 */
    double base = NORMAL_RATE * (0.7 + 0.5 * sin(2 * M_PI * day_phase));

    /* Add random micro-burst */
    if ((rand() % 100) < 5)
        base *= (1.0 + (rand() % 100) / 50.0);

    return base;
}

struct workload_mix {
    double ratios[WORK_CLASS_MAX]; /* Sum to 1.0 */
};

struct workload_mix MIX_NORMAL = {
  .ratios = {
    [WORK_CRITICAL] = 0.01,   /* 1% control frames */
    [WORK_LATENCY] = 0.19,    /* 19% interactive */
    [WORK_THROUGHPUT] = 0.75, /* 75% bulk data */
    [WORK_MAINTENANCE] = 0.05 /* 5% maintenance */
  },
};

struct workload_mix MIX_HANDSHAKE_HEAVY = {
  .ratios = {
    [WORK_CRITICAL] = 0.02,
    [WORK_LATENCY] = 0.48,
    [WORK_THROUGHPUT] = 0.45,
    [WORK_MAINTENANCE] = 0.05,
  },
};

struct workload_mix MIX_CONTROL_HEAVY = {
  .ratios = {
    [WORK_CRITICAL] = 0.15,
    [WORK_LATENCY] = 0.20,
    [WORK_THROUGHPUT] = 0.60,
    [WORK_MAINTENANCE] = 0.05,
  },
};

/* NUMA Topology Models */
struct numa_config {
    int num_nodes;
    double local_cost;      /* Cost multiplier for local access */
    double remote_cost;     /* Cost multiplier for remotr access */
    double steal_threshold; /* When stealing becomes beneficial */
};

struct numa_config NUMA_NONE = {
  .num_nodes = 1,
  .local_cost = 1.0,
  .remote_cost = 1.0,
  .steal_threshold = 0.9};

struct numa_config NUMA_2_SOCKET = {
  .num_nodes = 2,
  .local_cost = 1.0,
  .remote_cost = 1.3, /* 30% penalty for remote */
  .steal_threshold = 0.7};

struct numa_config NUMA_4_SOCKET = {
  .num_nodes = 4,
  .local_cost = 1.0,
  .remote_cost = 1.5, /* 50% penalty for remote */
  .steal_threshold = 0.5};

/* Feedback Controller State */
struct feedback {
    /* Measurements */
    double p50_latency;
    double p95_latency;
    double p99_latency;
    double queue_depth;
    double utilization;
    double drift;
    double pressure;

    /* EWMA filtered values */
    double avg_latency;
    double avg_drift;
    double avg_pressure;

    /* Outputs */
    regime_t regime;
    __uint32_t max_slices_per_tick;
    double timeout_per_tick_us;
    double target_concurrency;

    /* History for Px calculation */
    double latency_history[MEASUREMENT_WINDOW];
    int history_idx;
};

struct scheduler {
    /* Per-class queues */
    double queue_depth[WORK_CLASS_MAX];
    double processed[WORK_CLASS_MAX];
    double slices_used[WORK_CLASS_MAX];

    /* Per-class slice budgets (static table) */
    __uint8_t slice_table[WORK_CLASS_MAX][REGIME_MAX];

    /* Connections */
    double total_connections;
    double active_connections;
    double idle_connections;

    /* Per-NUMA shards */
    struct {
        double active_conns;
        double idle_conns;
        double local_slices;
        double remote_slices;
        double steals;
    } numa_shard[4];
    int numa_nodes;
    struct numa_config *numa;

    /* Work stealing stats */
    double steal_attempts;
    double steal_success;
    double steal_penalty;

    /* Slice processing */
    double slice_per_tick;
    double slice_efficiency; /* Work done per slice */

    /* Jump table simulation */
    double class_overhead[WORK_CLASS_MAX];
};

/* Complete Simulation State */
struct sim_state {
    struct feedback fb;
    struct scheduler sched;

    /* Current tick */
    int tick;
    double arrival_rate;
    struct workload_mix *mix;

    /* Metrics collected */
    struct {
        double latency[WORK_CLASS_MAX];
        double throughput[WORK_CLASS_MAX];
        double queue[WORK_CLASS_MAX];
        double concurrency;
        double utilization;
        double steal_effectiveness;
    } metrics;
};

/* Initialize Static Slice Table */
static void init_slice_table(struct scheduler *s) {
    /* Base static table - our proven values */
    s->slice_table[WORK_CRITICAL][REGIME_IDLE] = 4;
    s->slice_table[WORK_CRITICAL][REGIME_NORMAL] = 4;
    s->slice_table[WORK_CRITICAL][REGIME_BUSY] = 4;
    s->slice_table[WORK_CRITICAL][REGIME_CRITICAL] = 4;

    s->slice_table[WORK_LATENCY][REGIME_IDLE] = 4;
    s->slice_table[WORK_LATENCY][REGIME_NORMAL] = 3;
    s->slice_table[WORK_LATENCY][REGIME_BUSY] = 3;
    s->slice_table[WORK_LATENCY][REGIME_CRITICAL] = 2;

    s->slice_table[WORK_THROUGHPUT][REGIME_IDLE] = 3;
    s->slice_table[WORK_THROUGHPUT][REGIME_NORMAL] = 2;
    s->slice_table[WORK_THROUGHPUT][REGIME_BUSY] = 1;
    s->slice_table[WORK_THROUGHPUT][REGIME_CRITICAL] = 0;

    s->slice_table[WORK_MAINTENANCE][REGIME_IDLE] = 3;
    s->slice_table[WORK_MAINTENANCE][REGIME_NORMAL] = 2;
    s->slice_table[WORK_MAINTENANCE][REGIME_BUSY] = 1;
    s->slice_table[WORK_MAINTENANCE][REGIME_CRITICAL] = 0;

    /* Class overhead (cycle per slice) */
    s->class_overhead[WORK_CRITICAL] = 0.5;    /* Lightweight */
    s->class_overhead[WORK_LATENCY] = 1.0;     /* Medium */
    s->class_overhead[WORK_THROUGHPUT] = 0.8;  /* Medium-light */
    s->class_overhead[WORK_MAINTENANCE] = 2.0; /* Heavy (cleanup) */
}

/* Advanced Feedback Controller */
static void feedback_update(struct feedback *fb, double instant_latency, double queue_depth, double concurrency) {
    /* Update latency history (circular buffer) */
    fb->latency_history[fb->history_idx] = instant_latency;

    /* calculate percentiles */
    double hist[MEASUREMENT_WINDOW];
    memcpy(hist, fb->latency_history, sizeof(hist));

    /* Simple sort for percentiles (optimized for small window) */
    for (int i = 0; i < MEASUREMENT_WINDOW - 1; ++i) {
        for (int j = i + 1; j < MEASUREMENT_WINDOW; j++) {
            if (hist[i] > hist[j]) {
                double tmp = hist[i];
                hist[i] = hist[j];
                hist[j] = tmp;
            }
        }
    }

    fb->p50_latency = hist[MEASUREMENT_WINDOW / 2];
    fb->p95_latency = hist[MEASUREMENT_WINDOW * 95 / 100];
    fb->p99_latency = hist[MEASUREMENT_WINDOW * 99 / 100];

    /* Calculate drift (rate of change) */
    double latency_delta = fb->p95_latency - fb->avg_latency;
    double instant_drift = latency_delta / (fb->avg_latency + 1.0);
    fb->drift = ALPHA * instant_drift + (1 - ALPHA) * fb->drift;

    /* Calculate pressure (queue depth normalized) */
    double instant_pressure = queue_depth / (concurrency + 1.0);
    fb->pressure = BETA * instant_pressure + (1 - BETA) * fb->pressure;

    /* Update averages */
    fb->avg_latency = GAMMA * instant_latency + (1 - GAMMA) * fb->avg_latency;

    /* Regime determination (multi factor) */
    double latency_ratio = fb->p95_latency / SLO_LATENCY_US;
    double pressure_ratio = fb->pressure / TARGET_UTILIZATION;

    if (latency_ratio > 1.5 || (latency_ratio > 1.2 && fb->drift > 0.1)) {
        fb->regime = REGIME_CRITICAL;
    } else if (latency_ratio > 1.0 || (pressure_ratio > 1.2 && fb->drift > 0)) {
        fb->regime = REGIME_BUSY;
    } else if (pressure_ratio < 0.6 && fb->drift < -0.05) {
        fb->regime = REGIME_IDLE;
    } else {
        fb->regime = REGIME_NORMAL;
    }

    /* Calculate max slices based on regime and latency */
    double base_slice = MAX_SLICES_PER_TICK;
    double latency_factor = (SLO_LATENCY_US / (fb->p95_latency + 1.0));

    switch (fb->regime) {
    case REGIME_IDLE:
        fb->max_slices_per_tick = (__uint32_t)(base_slice * 1.2);
        fb->timeout_per_tick_us = 2000; /* 2ms */
        break;

    case REGIME_NORMAL:
        fb->max_slices_per_tick = (__uint32_t)(base_slice * latency_factor);
        fb->timeout_per_tick_us = 1000; /* 1ms */
        break;

    case REGIME_BUSY:
        fb->max_slices_per_tick = (__uint32_t)(base_slice * 0.7 * latency_factor);
        fb->timeout_per_tick_us = 500; /* 0.5ms */
        break;

    case REGIME_CRITICAL:
        fb->max_slices_per_tick = (__uint32_t)(base_slice * 0.3);
        fb->timeout_per_tick_us = 250;
        break;
    }

    /* Ensure bounds */
    if (fb->max_slices_per_tick < 100)
        fb->max_slices_per_tick = 100;
    if (fb->max_slices_per_tick > 5000)
        fb->max_slices_per_tick = 5000;

    fb->target_concurrency = fb->max_slices_per_tick * 0.8; /* Heuristic */
}

/* NUMA-Aware Work Stealing Model */
static double simulate_work_stealing(struct scheduler *s, struct feedback *fb, double remaining_slices) {
    if (s->numa_nodes < 2 || remaining_slices < 10)
        return remaining_slices;

    double stolen = 0;
    double steal_budget = remaining_slices * 0.2; /* Max 20 percent for stealing */

    /* Find imbalanced shards */
    for (int i = 0; i < s->numa_nodes; ++i) {
        for (int j = 0; j < s->numa_nodes; ++j) {
            if (i == j)
                continue;

            double imbalance = s->numa_shard[i].active_conns - s->numa_shard[j].active_conns;
            /*Significant imbalance */
            if (imbalance > 5) {
                s->steal_attempts++;

                /* NUMA cost calculation */
                double cost = (i == j) ? s->numa->local_cost : s->numa->remote_cost;

                /* Only steal if beneficial */
                if (cost < 1.2 && steal_budget > 0) {
                    double steal_amount = fmin(imbalance * 0.3, steal_budget);
                    stolen += steal_amount;
                    steal_budget -= steal_amount;
                    s->steal_success++;
                    s->steal_penalty += (cost - 1.0) * steal_amount;

                    /* Update shard stats */
                    s->numa_shard[i].active_conns -= steal_amount / 10;
                    s->numa_shard[j].active_conns += steal_amount / 10;
                    s->numa_shard[j].remote_slices += steal_amount;
                }
            }
        }
    }

    return remaining_slices - stolen;
}

/* Active/Idle List seperation Model */
static void update_active_idle_lists(struct scheduler *s, double total_conns, double arrival_rate) {
    /* Connection become active when they have work */
    double new_active = arrival_rate * 0.1; /* Some arrivals create work */

    /* Connections become idle when no work */
    double work_completion = s->processed[WORK_CRITICAL] + s->processed[WORK_LATENCY] + s->processed[WORK_THROUGHPUT] + s->processed[WORK_MAINTENANCE];

    double new_idle = work_completion * 0.05; /* Some connections finish */

    /* Update active/idle counts with NUMA distribution */
    for (int i = 0; i < s->numa_nodes; ++i) {
        s->numa_shard[i].active_conns += new_active / s->numa_nodes;
        s->numa_shard[i].idle_conns += new_idle / s->numa_nodes;

        /* Bounds */
        if (s->numa_shard[i].active_conns > total_conns / s->numa_nodes)
            s->numa_shard[i].active_conns = total_conns / s->numa_nodes;
    }

    s->active_connections += new_active - new_idle;
    s->idle_connections += new_idle - new_active;

    /* Ensure bounds */
    if (s->active_connections < 0)
        s->active_connections = 0;
    if (s->idle_connections < 0)
        s->idle_connections = 0;
}

/* Slice distribution Model */
static void distrbute_slices(struct sim_state *state) {
    struct feedback *fb = &state->fb;
    struct scheduler *s = &state->sched;

    regime_t regime = fb->regime;
    __uint32_t total_slices = fb->max_slices_per_tick;
    __uint32_t slices_remaining = total_slices;

    /* Zero per-class counters */
    memset(s->slices_used, 0, sizeof(s->slices_used));
    memset(s->processed, 0, sizeof(s->processed));

    /* First pass: guarantee base slices to active connections */
    double active_per_class[WORK_CLASS_MAX] = {0};

    /* Estimate active connections per class based on workload mix */
    for (int c = 0; c < WORK_CLASS_MAX; c++) {
        active_per_class[c] = s->active_connections * state->mix->ratios[c];

        /* Calculate base slices needed */
        __uint32_t base_slices_needed = (__uint32_t)(active_per_class[c] * s->slice_table[c][regime]);

        __uint32_t slices_given = base_slices_needed;
        if (slices_given > slices_remaining)
            slices_given = slices_remaining;

        s->slices_used[c] = slices_given;
        slices_remaining -= slices_given;

        /* Record efficiency */
        s->processed[c] = slices_given * s->class_overhead[c];
    }

    /* Second pass: distribure remaining slices based on need */
    if (slices_remaining > 0) {
        double total_need = 0;
        double need_per_class[WORK_CLASS_MAX];

        for (int c = 0; c < WORK_CLASS_MAX; ++c) {
            need_per_class[c] = s->queue_depth[c] * state->mix->ratios[c];
            total_need += need_per_class[c];
        }

        if (total_need > 0) {
            for (int c = 0; c < WORK_CLASS_MAX; ++c) {
                __uint32_t extra = (__uint32_t)(slices_remaining * need_per_class[c] / total_need);
                s->slices_used[c] += extra;
                s->processed[c] += extra * s->class_overhead[c];
            }
        }
    }

    /* Work stealing if enabled and beneficial */
    if (slices_remaining > 10 && s->numa_nodes > 1) {
        slices_remaining = simulate_work_stealing(s, fb, slices_remaining);
    }

    s->slice_per_tick = total_slices - slices_remaining;
    s->slice_efficiency = (s->processed[0] + s->processed[1] + s->processed[2] + s->processed[3]) / (s->slice_per_tick + 1.0);
}

/* Process One Simulation Tick */
void simulate_tick(struct sim_state *state, double arrival_rate, struct workload_mix *mix) {
    state->tick++;
    state->arrival_rate = arrival_rate;
    state->mix = mix;

    struct feedback *fb = &state->fb;
    struct scheduler *s = &state->sched;

    /* 1.Arrivals - distribute by class */
    for (int c = 0; c < WORK_CLASS_MAX; ++c) {
        s->queue_depth[c] += arrival_rate * mix->ratios[c];
    }

    /* 2.Update active/idle lists */
    update_active_idle_lists(s, state->metrics.concurrency, arrival_rate);

    /* 3.Distribute slices based on feedback regime */
    distrbute_slices(state);

    /* 4.Process work */
    double total_processed = 0;
    double class_latency[WORK_CLASS_MAX] = {0};

    for (int c = 0; c < WORK_CLASS_MAX; ++c) {
        /* processed up to queue depth */
        double processed = fmin(s->processed[c], s->queue_depth[c]);
        s->queue_depth[c] -= processed;
        total_processed += processed;

        /* Calculate latency (little's law) */
        if (processed > 0) {
            class_latency[c] = BASE_LATENCY_US + (s->queue_depth[c] / (processed + 1.0));
        }

        state->metrics.throughput[c] = processed;
        state->metrics.queue[c] = s->queue_depth[c];
        state->metrics.latency[c] = class_latency[c];
    }

    /* 5.Update feedback controller and utilization */
    state->metrics.concurrency = s->active_connections;
    state->metrics.utilization = total_processed / (fb->max_slices_per_tick + 1.0);

    /* 6. Update feeback controller with overall latency */
    double overall_latency = class_latency[WORK_LATENCY] * 0.6 + class_latency[WORK_THROUGHPUT] * 0.4;

    feedback_update(fb, overall_latency,
                    s->queue_depth[0] + s->queue_depth[1] + s->queue_depth[2] + s->queue_depth[3],
                    state->metrics.concurrency);

    /* 7. Update steal effectiveness metric */
    if (s->steal_attempts > 0) {
        state->metrics.steal_effectiveness = s->steal_success / s->steal_attempts;
    }
}

/* Print Simulation Results */
void print_results(struct sim_state *state, int ticks, const char *scenario) {
    printf("\n================================================\n");
    printf("SCENARIO: %s\n", scenario);
    printf("\n================================================\n");

    /* Average metrics over last half of simulation */
    printf("\nFINAL STATE:\n");
    printf(" Regime: %d\n", state->fb.regime);
    printf(" Max slices/tick: %u\n", state->fb.max_slices_per_tick);
    printf(" Timeout: %.0f us\n", state->fb.timeout_per_tick_us);
    printf(" Concurrency: %.1f\n", state->metrics.concurrency);
    printf(" Utilization: %.2f\n", state->metrics.utilization);

    printf("\nPER CLASS:\n");
    const char *class_name[] = {"Critical", "Latency", "Throughput", "Maintenance"};
    for (int c = 0; c < WORK_CLASS_MAX; ++c) {
        printf(" %-12s queue: %8.1f latency: %8.1f us\n", class_name[c], state->metrics.queue[c], state->metrics.latency[c]);
    }

    printf("\nSCHEDULER:\n");
    printf(" Active connection: %1.f\n", state->sched.active_connections);
    printf(" Idle connection: %1.f\n", state->sched.idle_connections);
    printf(" Slice efficiency: %.2f work/slice\n", state->sched.slice_efficiency);
    printf(" Work stealing: %.1f%% success\n", state->metrics.steal_effectiveness * 100);

    if (state->sched.numa_nodes > 1) {
        printf("\nNUMA EFFECTS:\n");
        printf(" Remote access penalty: %.2f slices lost\n", state->sched.steal_penalty);
        for (int i = 0; i < state->sched.numa_nodes; ++i) {
            printf(" Shared %d: active=%.0f remote=%.0f\n", i,
                   state->sched.numa_shard[i].active_conns,
                   state->sched.numa_shard[i].remote_slices);
        }
    }
}

/* Run Simulation Scenario */
void run_scenario(const char *name, struct pattern *pattern, struct workload_mix *mix, struct numa_config *numa) {
    struct sim_state state = {0};

    /* Initialize */
    init_slice_table(&state.sched);
    state.sched.numa = numa;
    state.sched.numa_nodes = numa->num_nodes;
    state.fb.avg_latency = BASE_LATENCY_US;
    state.fb.max_slices_per_tick = MAX_SLICES_PER_TICK;
    state.metrics.concurrency = 100; /* Start with 100 connections */

    /* Warmup */
    for (int t = 0; t < WARMUP_TICKS; ++t) {
        double rate = pattern->rate_at(t);
        simulate_tick(&state, rate, mix);
    }

    /* Measurement */
    for (int i = WARMUP_TICKS; i < A_SIM_TICKS; ++i) {
        double rate = pattern->rate_at(i);
        simulate_tick(&state, rate, mix);
    }

    print_results(&state, A_SIM_TICKS, name);
}

/* Run all Scenarios */
int main() {
    printf("EDGE-NATIVE TWS SCHEDULER SIMULATOR\n");
    printf("=====================================");

    /* Seed random for diurnal pattern */
    srand(42);

    /* Define patterns */
    struct pattern square_pattern = {"Square Wave Burst", square_wave_rate};
    struct pattern sine_pattern = {"Square Wave Load", sine_wave_rate};
    struct pattern step_pattern = {"Step Increase", step_rate};
    struct pattern diurnal_pattern = {"Diurnal Pattern", diurnal_rate};

    /* Run scenarios */
    run_scenario("Normal Web Traffic", &square_pattern, &MIX_NORMAL, &NUMA_2_SOCKET);
    run_scenario("Handshake Heavy (Flash crowd)", &step_pattern, &MIX_HANDSHAKE_HEAVY, &NUMA_2_SOCKET);
    run_scenario("Control Heavy (GOAWAY Storm)", &sine_pattern, &MIX_CONTROL_HEAVY, &NUMA_2_SOCKET);
    run_scenario("NUMA 4-Socket Scaling", &diurnal_pattern, &MIX_NORMAL, &NUMA_4_SOCKET);

    return 0;
}