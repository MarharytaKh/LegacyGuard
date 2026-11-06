/*
 * common.h - shared constants, error codes and small string helpers.
 */
#ifndef LG_COMMON_H
#define LG_COMMON_H

#include <stddef.h>

#define LG_NAME_MAX     64
#define LG_VERSION_MAX  32
#define LG_ID_MAX       32
#define LG_PATH_MAX     256
#define LG_DESC_MAX     256
#define LG_LINE_MAX     1024

typedef enum {
    LG_OK = 0,
    LG_ERR_IO = -1,        /* file cannot be opened / read / written       */
    LG_ERR_FORMAT = -2,    /* malformed input line or patch                */
    LG_ERR_NOT_FOUND = -3, /* package / patch / file does not exist        */
    LG_ERR_EXISTS = -4,    /* duplicate entry                              */
    LG_ERR_VERSION = -5,   /* invalid version string                       */
    LG_ERR_NOMEM = -6,     /* allocation failure                           */
    LG_ERR_CONFLICT = -7,  /* patch does not apply                         */
    LG_ERR_STATE = -8      /* e.g. patch already applied / not applied     */
} lg_status;

const char *lg_strerror(lg_status st);

/* Copy at most dst_size-1 bytes and always NUL-terminate. */
void lg_strlcpy(char *dst, const char *src, size_t dst_size);

/* Remove leading/trailing whitespace in place, returns s. */
char *lg_trim(char *s);

/*
 * Split a '|'-separated line in place. Stores up to max_fields pointers
 * in fields and returns the number of fields found.
 */
int lg_split(char *line, char sep, char **fields, int max_fields);

/* Returns 1 if the line is empty or a '#' comment. */
int lg_is_blank_or_comment(const char *line);

#endif /* LG_COMMON_H */
