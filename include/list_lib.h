#ifndef AURA_LIST_H
#define AURA_LIST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#define a_container_of(ptr, type, member) ({          \
    const typeof(((type *)0)->member) *_mptr = (ptr); \
    (type *)((char *)_mptr - offsetof(type, member)); \
})

struct aura_list_head {
    struct aura_list_head *next, *prev;
};

static inline void a_list_head_init(struct aura_list_head *list) {
    list->next = list;
    list->prev = list;
}

static inline void _a_list_add(struct aura_list_head *prev, struct aura_list_head *next, struct aura_list_head *_new) {
    next->prev = _new;
    _new->next = next;
    _new->prev = prev;
    prev->next = _new;
}

static inline void a_list_add(struct aura_list_head *head, struct aura_list_head *_new) {
    _a_list_add(head, head->next, _new);
}

static inline void a_list_add_tail(struct aura_list_head *head, struct aura_list_head *_new) {
    _a_list_add(head->prev, head, _new);
}

static inline void a_list_delete(struct aura_list_head *entry) {
    entry->next->prev = entry->prev;
    entry->prev->next = entry->next;
}

static inline void a_list_replace(struct aura_list_head *new_, struct aura_list_head *old) {
    new_->next = old->next;
    new_->prev = old->prev;
    new_->next->prev = new_;
    new_->prev->next = new_;
}

static inline void a_list_move(struct aura_list_head *head, struct aura_list_head *entry) {
    a_list_delete(entry);
    a_list_add(head, entry);
}

static inline void a_list_move_tail(struct aura_list_head *head, struct aura_list_head *entry) {
    a_list_delete(entry);
    a_list_add_tail(head, entry);
}

static inline bool a_list_is_empty(struct aura_list_head *head) {
    return head->next == head; /** @todo: use likely collection here */
}

static inline bool a_entry_is_last(struct aura_list_head *head, struct aura_list_head *entry) {
    return entry->next == head;
}

#define a_list_entry(ptr, type, member) a_container_of(ptr, type, member)

#define a_list_first_entry(head, type, member) a_list_entry((head)->next, type, member)

#define a_list_next_entry(cursor, type, member) a_list_entry(cursor->member.next, type, member)

#define a_list_for_each(cursor, head, member) \
    for (cursor = a_list_first_entry(head, typeof(*cursor), member); &cursor->member != (head); cursor = a_list_next_entry(cursor, typeof(*cursor), member))

/**
 * This is deletion safe version of the normal iterator
 * It doesn't distort the pointers while deleting
 */
#define a_list_for_each_safe_to_delete(cursor, pos, head, member) \
    for (cursor = a_list_first_entry(head, typeof(*cursor), member), pos = a_list_next_entry(cursor, typeof(*cursor), member); &cursor->member != (head); cursor = pos)

#define a_list_dequeue(cursor, head, member)                        \
    {                                                               \
        cursor = a_list_first_entry(head, typeof(*cursor), member); \
        if (&cursor->member == head)                                \
            cursor = NULL;                                          \
        else                                                        \
            a_list_delete(&cursor->member);                         \
    }

#endif