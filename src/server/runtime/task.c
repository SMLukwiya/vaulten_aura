#include "header_srv.h"
#include "http_lib.h"
#include "runtime/request.h"
#include "string_lib.h"
#include "task_srv.h"

struct aura_task *aura_task_create(struct aura_memory_ctx *mc, uint64_t next_id, void *conn,
                                   void *stream, a_task_protocol_t prot, char *url, int method,
                                   struct aura_header_vector *headers, char *body, size_t body_len) {
    struct aura_task *task;
    Request *req;
    Response *resp;
    app_debug(true, 0, "aura__task_create <<<<");

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
    req->method = method;
    for (int i = 0; i < headers->cnt; ++i) {
        struct aura_rt_header_field *hdr_slot;
        struct aura_header_field *hdr_field;

        hdr_slot = aura_rt_req_get_header_slot(mc, req);
        if (!hdr_slot) {
            aura_rt_req_destroy(req);
            aura_free(task);
            return NULL;
        }
        hdr_field = &headers->entries[i];
        hdr_slot->name.base = aura_strndup(mc, hdr_field->name.interned->data, hdr_field->name.interned->len);
        if (hdr_field->value_interned)
            hdr_slot->value.base = aura_strndup(mc, hdr_field->value.interned->data, hdr_field->value.interned->len);
        else
            hdr_slot->value.base = aura_strndup(mc, hdr_field->value.raw.str->base, hdr_field->value.raw.str->len);
    }
    req->body = NULL;
    req->body_len = 0;
    /* @todo: add the stuff on the requests */
    if (req->method == HTTP_POST) {
        req->body = body;
        req->body_len = body_len;
    }

    task = aura_alloc(mc, sizeof(*task));
    if (!task) {
        aura_rt_req_destroy(req);
        aura_rt_res_destroy(resp);
        return NULL;
    }
    memset(task, 0, sizeof(task));

    a_list_head_init(&task->t_list);
    task->id = next_id;
    task->conn = conn;
    task->stream = stream;
    task->req_data = req;
    task->res_data = resp;
    task->state = A_TASK_STATE_QUEUED;
    task->protocol = prot;

    return task;
}

void aura_task_destroy(struct aura_task *task) {
    if (!task)
        return;

    if (task->req_data)
        aura_rt_req_destroy(task->req_data);

    if (task->res_data)
        aura_rt_res_destroy(task->res_data);
}

void aura_task_dump(struct aura_task *task) {
    app_debug(true, 0, "AURA_TASK");
    app_debug(true, 0, "    Id: %lu", task->id);
    app_debug(true, 0, "    State: %d", task->state);
    app_debug(true, 0, "    Protocol: %d", task->protocol);
}