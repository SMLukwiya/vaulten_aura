#ifndef AURA_SRV_TASK_H
#define AURA_SRV_TASK_H

#include "header_srv.h"
#include "list_lib.h"
#include "memory_lib.h"
#include "quickjs/quickjs.h"

#include <stdbool.h>

/* JS request object */
typedef struct aura_js_request {
    int method;
    const char *url;
    struct aura_http_hdrs *headers;
    const uint8_t *body;
    size_t body_len;
    JSValue obj;
} Request;

/* JS response object */
typedef struct aura_js_response {
    uint16_t status;
    struct aura_http_hdrs *headers;
    const uint8_t *body;
    size_t body_len;
    JSValue obj;
} Response;

/* Generic Task structure */
struct aura_task {
    struct aura_memory_ctx *mc;
    uint32_t stream_id;
    void *data;
    void (*on_completion_cb)(struct aura_task *task, JSValue result);
    struct aura_list_head t_list;
    uint64_t started_at;
    uint64_t completed_at;
};

#endif