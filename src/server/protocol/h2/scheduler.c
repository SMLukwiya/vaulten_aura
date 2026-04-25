#include "h2/scheduler.h"
#include "h2/h2_srv.h"
#include "h2/stream.h"
#include "list_lib.h"
#include "time_lib.h"

#define MILLISECOND 1000000

struct aura_h2_sched_evt *aura_sched_evt_create(struct aura_memory_ctx *mc, struct aura_h2_stream *stream,
                                                struct aura_sliding_buf *buf, aura_h2_scheduler_current_op_t op,
                                                uint8_t *encoded_data, size_t encoded_len, bool end_stream) {
    struct aura_h2_sched_evt *evt;

    evt = aura_alloc(mc, sizeof(*evt));
    if (!evt)
        return NULL;

    app_debug(true, 0, "aura_sched_evt_create <<< OP: %d", op);
    evt->buf = buf;
    evt->op = op;
    evt->end_stream = end_stream;
    evt->encoded.data = encoded_data;
    evt->encoded.len = encoded_len;
    evt->stream = stream;
    a_list_head_init(&evt->e_list);

    return evt;
}

static struct aura_h2_sched_evt *a_h2_schedule_next_evt(struct aura_h2_scheduler *sched) {
    struct aura_h2_sched_evt *evt;
    uint64_t now;

    if (!a_list_is_empty(&sched->queues.urgent.head)) {
        evt = a_list_first_entry(&sched->queues.urgent.head, struct aura_h2_sched_evt, e_list);
        return evt;
    }

    /* control, things can can create new streams */
    if (!a_list_is_empty(&sched->queues.control.head)) {
        now = aura_now_ms(CLOCK_REALTIME);
        if (now - sched->last_tick_time > MILLISECOND) {
            evt = a_list_first_entry(&sched->queues.control.head, struct aura_h2_sched_evt, e_list);
            return evt;
        }
    }

    /* select next data frame */
    if (!a_list_is_empty(&sched->queues.data.head)) {
        evt = a_list_first_entry(&sched->queues.data.head, struct aura_h2_sched_evt, e_list);
        /* We can split header and data frames how we want */
        return evt;
    }

    return NULL;
}

void aura_h2_scheduler_evt_destroy(struct aura_h2_sched_evt *evt) {
    if (!evt)
        return;

    aura_free(evt);
}

int aura_h2_schedule(struct aura_conn *conn, void *dest) {
    struct aura_h2_ctx *h2_ctx;
    struct aura_h2_scheduler *scheduler;
    struct aura_h2_sched_evt *evt;
    struct aura_h2_send_iov *iov_slot;
    struct iovec iov;

    app_debug(true, 0, "aura_h2_schedule <<<");
    iov_slot = dest; /* iov array passed from out */
    h2_ctx = conn->protocol_ctx.ctx;
    if (!h2_ctx)
        return -1;

    scheduler = &h2_ctx->scheduler;
    evt = a_h2_schedule_next_evt(scheduler);
    if (!evt)
        return -1;

    switch (evt->op) {
    case AURA_H2_SCHED_OP_URGENT_WRITE:
    case AURA_H2_SCHED_OP_CONTROL_WRITE:
        iov_slot->iov.iov_base = evt->encoded.data;
        iov_slot->iov.iov_len = evt->encoded.len;
        iov_slot->buf = evt->buf;
        a_list_delete(&evt->e_list);
        aura_h2_scheduler_evt_destroy(evt);
        break;

    case AURA_H2_SCHED_OP_HEADER_WRITE:
        if (!aura_h2_stream_can_send(evt->stream))
            return -1;
        iov = aura_sliding_buffer_get_read_iovec(evt->stream->sync, UINT64_MAX);
        iov_slot->iov.iov_base = iov.iov_base;
        iov_slot->iov.iov_len = iov.iov_len;
        iov_slot->buf = evt->stream->sync;
        a_list_delete(&evt->e_list);
        aura_h2_scheduler_evt_destroy(evt);
        break;

    case AURA_H2_SCHED_OP_DATA_WRITE:
        size_t write_size, offset, chunk, flags;
        const char *start;
        bool end_stream;
        if (!aura_h2_stream_can_send(evt->stream))
            return -1;

        write_size = aura_h2_conn_get_flow_control_size(h2_ctx, evt->stream);
        write_size = a_min(write_size, evt->stream->res.content_length);
        if (write_size == 0) {
            aura_h2_stream_pause(evt->stream);
            return 0;
        }

        start = evt->stream->res.body;
        offset = flags = 0;
        end_stream = evt->stream->res.content_length == write_size;
        while (write_size > 0) {
            chunk = a_min(write_size, h2_ctx->peer_settings.max_frame_size);
            flags |= (write_size == chunk && end_stream) ? A_H2_FRAME_FLAG_END_STREAM : 0;
            if (aura_encode_data_frame(evt->stream->data, evt->stream->stream_id, flags, start + offset, chunk, 0) < 0)
                return -1;

            offset += chunk;
            write_size -= chunk;
            evt->stream->res.content_length -= chunk;
        }
        iov = aura_sliding_buffer_get_read_iovec(evt->stream->data, UINT64_MAX);
        iov_slot->iov.iov_base = iov.iov_base;
        iov_slot->iov.iov_len = iov.iov_len;
        iov_slot->buf = evt->stream->data;
        /* Remove when stream body is done */

        if (end_stream) {
            a_list_delete(&evt->e_list);
            aura_h2_scheduler_evt_destroy(evt);
        }
        break;
    default:
        return -1;
    }

    return 0;
}