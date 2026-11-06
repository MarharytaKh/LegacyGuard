/*
 * Simplified training copy (LegacyGuard test data).
 */
#ifndef HEADER_BUFFER_H
#define HEADER_BUFFER_H

#include <stddef.h>

#define BUF_MEM_FLAG_SECURE 0x01

typedef struct buf_mem_st {
    size_t length;
    char *data;
    size_t max;
    unsigned long flags;
} BUF_MEM;

BUF_MEM *BUF_MEM_new(void);
BUF_MEM *BUF_MEM_new_ex(unsigned long flags);
void BUF_MEM_free(BUF_MEM *a);
size_t BUF_MEM_grow(BUF_MEM *str, size_t len);
size_t BUF_MEM_grow_clean(BUF_MEM *str, size_t len);

#endif
