#include "header_srv.h"
#include "http_lib.h"
#include "runtime/request.h"
#include "string_lib.h"
#include "task_srv.h"

struct _aura_task *aura_task_create(struct aura_h2_stream *stream, struct aura_mem_ctx *mc,
                                    uint8_t *url, uint64_t next_id, uint32_t conn_id,
                                    uint32_t conn_idx, a_task_protocol_t prot) {
    struct _aura_task *task;
    _Request *req;
    _Response *resp;

    /* Create request holder */
    req = aura_rt_create_req(mc);
    if (!req)
        return NULL;

    /* Create response holder */
    resp = aura_rt_create_res(mc);
    if (!resp) {
        aura_rt_req_destroy(req);
        return NULL;
    }

    req->url.base = aura_strdup(mc, url);
    req->method = stream->req.method;

    req->headers.cnt = req->headers.cap = 0;
    if (stream->req.headers.entries && stream->req.headers.cnt > 0) {
        req->headers.entries = aura_alloc(mc, sizeof(*req->headers.entries) * stream->req.headers.cnt);
        if (!req->headers.entries) {
            aura_rt_req_destroy(req);
            aura_rt_res_destroy(resp);
            return NULL;
        }

        // struct aura_basic_header *hdr_slot, *hdr_field;
        /* Take ownership of headers */
        for (int i = 0; i < stream->req.headers.cnt; ++i) {
            req->headers.entries[i] = stream->req.headers.entries[i];
            req->headers.cnt++;
        }
        /* Set header count on stream request to release headers */
        stream->req.headers.cnt = 0;
    }

    req->body = NULL;
    req->body_len = 0;
    /* @todo: add the stuff on the requests */
    if (req->method == A_HTTP_POST) {
        req->body = stream->req.body;
        req->body_len = stream->req.content_length;
        stream->req.body = NULL;
        stream->req.content_length = 0;
    }

    task = aura_alloc(mc, sizeof(*task));
    if (!task) {
        aura_rt_req_destroy(req);
        aura_rt_res_destroy(resp);
        return NULL;
    }
    memset(task, 0, sizeof(task));

    aura_list_head_init(&task->t_list);
    task->id = next_id;
    task->conn_id = conn_id;
    task->conn_idx = conn_idx;
    task->stream_id = stream->stream_id;
    task->req_data = req;
    task->res_data = resp;
    task->state = A_TASK_STATE_QUEUED;
    task->protocol = prot;

    return task;
}

void aura_task_destroy(struct _aura_task *task) {
    if (!task)
        return;

    if (task->req_data)
        aura_rt_req_destroy(task->req_data);

    if (task->res_data)
        aura_rt_res_destroy(task->res_data);
}

void aura_task_dump(struct _aura_task *task) {
    app_debug(true, 0, "AURA_TASK");
    app_debug(true, 0, "    Id: %lu", task->id);
    app_debug(true, 0, "    State: %d", task->state);
    app_debug(true, 0, "    Protocol: %d", task->protocol);
}