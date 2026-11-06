#include "common.h"

#include <ctype.h>
#include <string.h>

const char *lg_strerror(lg_status st)
{
    switch (st) {
    case LG_OK:            return "success";
    case LG_ERR_IO:        return "I/O error";
    case LG_ERR_FORMAT:    return "invalid format";
    case LG_ERR_NOT_FOUND: return "not found";
    case LG_ERR_EXISTS:    return "already exists";
    case LG_ERR_VERSION:   return "invalid version string";
    case LG_ERR_NOMEM:     return "out of memory";
    case LG_ERR_CONFLICT:  return "patch conflict";
    case LG_ERR_STATE:     return "invalid state";
    }
    return "unknown error";
}

void lg_strlcpy(char *dst, const char *src, size_t dst_size)
{
    if (dst_size == 0)
        return;
    size_t n = strlen(src);
    if (n >= dst_size)
        n = dst_size - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

char *lg_trim(char *s)
{
    char *start = s;
    while (*start && isspace((unsigned char)*start))
        start++;
    if (start != s)
        memmove(s, start, strlen(start) + 1);

    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1]))
        s[--len] = '\0';
    return s;
}

int lg_split(char *line, char sep, char **fields, int max_fields)
{
    int n = 0;
    char *p = line;

    while (n < max_fields) {
        fields[n++] = p;
        char *next = strchr(p, sep);
        if (!next)
            break;
        *next = '\0';
        p = next + 1;
    }
    for (int i = 0; i < n; i++)
        lg_trim(fields[i]);
    return n;
}

int lg_is_blank_or_comment(const char *line)
{
    while (*line && isspace((unsigned char)*line))
        line++;
    return *line == '\0' || *line == '#';
}
