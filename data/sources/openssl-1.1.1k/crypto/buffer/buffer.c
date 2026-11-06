/*
 * Simplified training copy of a 1.1.1-era buffer module.
 * Part of the LegacyGuard test data: not the real OpenSSL source.
 */

#include <stdio.h>
#include <string.h>
#include <openssl/buffer.h>
#include <openssl/buffererr.h>
#include <openssl/err.h>

/*
 * LIMIT_BEFORE_EXPANSION is the maximum n such that (n+3)/3*4 < 2**31.
 * That function is applied in several functions in this file and this
 * limit ensures that the result fits in an int.
 */
#define LIMIT_BEFORE_EXPANSION 0x5ffffffc

BUF_MEM *BUF_MEM_new_ex(unsigned long flags)
{
    BUF_MEM *ret;

    ret = BUF_MEM_new();
    if (ret != NULL)
        ret->flags = flags;
    return ret;
}

BUF_MEM *BUF_MEM_new(void)
{
    BUF_MEM *ret;

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL) {
        BUFerr(BUF_F_BUF_MEM_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    return ret;
}

void BUF_MEM_free(BUF_MEM *a)
{
    if (a == NULL)
        return;
    if (a->data != NULL) {
        if (a->flags & BUF_MEM_FLAG_SECURE)
            OPENSSL_secure_clear_free(a->data, a->max);
        else
            OPENSSL_clear_free(a->data, a->max);
    }
    OPENSSL_free(a);
}

/* Allocate a block of secure memory; copy over old data if there
 * was any, and then free it. */
static char *sec_alloc_realloc(BUF_MEM *str, size_t len)
{
    char *ret;

    ret = OPENSSL_secure_malloc(len);
    if (str->data != NULL) {
        if (ret != NULL) {
            memcpy(ret, str->data, str->length);
            OPENSSL_secure_clear_free(str->data, str->length);
            str->data = NULL;
        }
    }
    return ret;
}

size_t BUF_MEM_grow(BUF_MEM *str, size_t len)
{
    char *ret;
    size_t n;

    if (str->length >= len) {
        str->length = len;
        return len;
    }
    if (str->max >= len) {
        if (str->data != NULL)
            memset(&str->data[str->length], 0, len - str->length);
        str->length = len;
        return len;
    }
    n = (len + 3) / 3 * 4;
    if ((str->flags & BUF_MEM_FLAG_SECURE))
        ret = sec_alloc_realloc(str, n);
    else
        ret = OPENSSL_realloc(str->data, n);
    if (ret == NULL) {
        BUFerr(BUF_F_BUF_MEM_GROW, ERR_R_MALLOC_FAILURE);
        len = 0;
    } else {
        str->data = ret;
        str->max = n;
        memset(&str->data[str->length], 0, len - str->length);
        str->length = len;
    }
    return len;
}

size_t BUF_MEM_grow_clean(BUF_MEM *str, size_t len)
{
    char *ret;
    size_t n;

    if (str->length >= len) {
        if (str->data != NULL)
            memset(&str->data[len], 0, str->length - len);
        str->length = len;
        return len;
    }
    if (str->max >= len) {
        memset(&str->data[str->length], 0, len - str->length);
        str->length = len;
        return len;
    }
    n = (len + 3) / 3 * 4;
    if ((str->flags & BUF_MEM_FLAG_SECURE))
        ret = sec_alloc_realloc(str, n);
    else
        ret = OPENSSL_clear_realloc(str->data, str->max, n);
    if (ret == NULL) {
        BUFerr(BUF_F_BUF_MEM_GROW_CLEAN, ERR_R_MALLOC_FAILURE);
        len = 0;
    } else {
        str->data = ret;
        str->max = n;
        memset(&str->data[str->length], 0, len - str->length);
        str->length = len;
    }
    return len;
}
