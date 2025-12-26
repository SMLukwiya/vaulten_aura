#include "h2/scheduler.h"
#include "list_lib.h"
#include "time_lib.h"

#define MILLISECOND 1000000

struct aura_h2_out_frame *aura_schedule_next_frame(struct aura_h2_sender_engine *engine) {
    struct aura_h2_out_frame *f;
    uint64_t now;

    /* Urgent frames */
    /* @todo: control inorder not to starve the control and data queue */
    if (!a_list_is_empty(&engine->queues.urgent.head)) {
        a_list_dequeue(f, &engine->queues.urgent.head, f_list);
        return f;
    }

    /* control, things can can create new streams */
    if (!a_list_is_empty(&engine->queues.control.head)) {
        now = aura_now_ms();
        if (now - engine->last_tick_time > MILLISECOND) {
            a_list_dequeue(f, &engine->queues.control.head, f_list);
            return f;
        }
    }

    /* select next data frame */
    if (!a_list_is_empty(&engine->queues.data.head)) {
        a_list_dequeue(f, &engine->queues.data.head, f_list);
        return f;
    }

    return NULL;
}

void edge_send_loop(struct aura_h2_conn *conn) {
    struct aura_h2_sender_engine *engine;
    struct aura_h2_out_frame *out_frame;
    uint64_t now;

    engine = &conn->sender;

    while (true) {
        /* Apply rate limiting for edge fairness */
        if (engine->bytes_sent_this_tick >= engine->max_bytes_per_tick) {
            now = aura_now_ms();
            /* 1us*/
            if (now - engine->last_tick_time < 1000) {
                /* Throttle for fairness */
                usleep(1);
                continue;
            }

            engine->bytes_sent_this_tick = 0;
            engine->last_tick_time = now;
        }

        out_frame = aura_schedule_next_frame(engine);
        if (!out_frame)
            break;

        now = aura_now_ms();
        // if (now > frame->deadline) {
        //     /* */
        // }
    }
}