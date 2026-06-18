#include <sys/eventfd.h>
#include <unistd.h>

#include "runtime/completions.h"

int aura_completion_queue_init(struct aura_completion_queue *cq) {
    memset(cq, 0, sizeof(*cq));

    if (pthread_mutex_init(&cq->lock, NULL))
        return -1;

    cq->efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (cq->efd < 0) {
        pthread_mutex_destroy(&cq->lock);
        return -1;
    }

    aura_list_head_init(&cq->list);
    return 0;
}

void aura_completion_destroy(struct aura_completion *c) {
    if (!c)
        return;

    if (c->task)
        aura_task_destroy(c->task);
}

void aura_completion_queue_destroy(struct aura_completion_queue *cq) {
    struct aura_completion *c;

    while (!aura_list_is_empty(&cq->list)) {
        a_list_dequeue(c, &cq->list, c_list);
        aura_completion_destroy(c);
    }

    pthread_mutex_destroy(&cq->lock);
    close(cq->efd);
}

int aura_completion_queue_push(struct aura_completion_queue *cq, struct aura_completion *c) {
    uint64_t one = 1;
    app_debug(true, 0, "aura_completion_queue_push <<<<");

    pthread_mutex_lock(&cq->lock);
    aura_list_add_tail(&cq->list, &c->c_list);
    pthread_mutex_unlock(&cq->lock);
    cq->cnt++;

    /* Notify epoll @todo: there may be no need to notify */
    // write(cq->efd, &one, sizeof(one));

    return 0;
}