#include "broker.h"

static struct aura_db_broker_request *a_db_brokered_req_create(struct aura_mem_ctx *mc, ns_t ns,
                                                               schema_id_t schema_id, struct aura_iovec *key,
                                                               struct aura_iovec *data, size_t *olen) {
    struct aura_db_broker_request *request;
    size_t len;

    *olen = 0;
    len = sizeof(*request) + key->len;
    if (data)
        len += data->len;
    *olen = len;

    request = aura_alloc(mc, len);
    if (!request)
        return NULL;
    memset(request, 0, len);

    request->namespace = ns;
    request->schema_id = schema_id;
    request->key.len = key->len;
    request->key.base = (char *)request + sizeof(*request);
    memcpy(request->key.base, key->base, key->len);
    if (data) {
        request->data.len = data->len;
        request->data.base = request->key.base + key->len;
        memcpy(request->data.base, data->base, data->len);
    } else {
        request->data.len = 0;
        request->data.base = NULL;
    }

    return request;
}

static inline void a_db_brokered_req_destroy(struct aura_db_broker_request *req) {
    if (req)
        aura_free(req);
}

int aura_db_brokered_fetch(struct aura_mem_ctx *mc, ns_t ns, schema_id_t schema_id,
                           struct aura_iovec *key, struct aura_iovec *out_data,
                           int dmn_fd) {
    struct aura_db_broker_request *request;
    struct aura_msg_hdr msg_hdr;
    struct aura_msg msg;
    struct aura_iovec data;
    size_t len;
    void *resp_data;
    int res;

    request = a_db_brokered_req_create(mc, ns, schema_id, key, NULL, &len);
    if (!request)
        return -1;

    a_init_msg_hdr(msg_hdr, len, A_MSG_CMD_EXECUTE, A_CMD_DB_FETCH_REQUEST);
    res = aura_msg_send(dmn_fd, &msg_hdr, (void *)request, len, -1);
    a_db_brokered_req_destroy(request);
    if (res < 0)
        return -1;

    res = aura_recv_resp(&data, dmn_fd, mc);
    if (res < 0)
        return -1;

    out_data->base = data.base;
    out_data->len = data.len;

    return 0;
}

int aura_db_brokered_insert(struct aura_mem_ctx *mc, ns_t ns, schema_id_t schema_id,
                            struct aura_iovec *key, struct aura_iovec *data,
                            aura_db_exec_mode mode, int dmn_fd) {
    struct aura_db_broker_request *request;
    struct aura_msg_hdr msg_hdr;
    struct aura_msg msg;
    size_t len;
    int res;

    request = a_db_brokered_req_create(mc, ns, schema_id, key, data, &len);
    if (!request)
        return -1;

    a_init_msg_hdr(msg_hdr, len, A_MSG_CMD_EXECUTE, A_CMD_DB_INSERT_REQUEST);
    res = aura_msg_send(dmn_fd, &msg_hdr, (void *)request, len, -1);
    a_db_brokered_req_destroy(request);
    if (res < 0)
        return res;

    /* Perform synchronous action */
    if (mode == A_DB_EXEC_SYNC) {
        res = aura_msg_recv(dmn_fd, &msg);
        if (res <= 0)
            return res;
    }
    return 0;
}

void aura_db_request_dump(struct aura_db_broker_request *req) {
    app_debug(true, 0, "AURA DB REQUEST");
    app_debug(true, 0, "    Namespace: %u", req->namespace);
    app_debug(true, 0, "    Schema_id: %u", req->schema_id);
    app_debug(true, 0, "    Key: %s", req->key.base);
}