#include "version.h"

#include <ctype.h>
#include <string.h>

static int is_separator(char c)
{
    return c != '\0' && c != '~' && !isalnum((unsigned char)c);
}

/* Compare two runs of digits numerically without overflowing. */
static int compare_numeric(const char *a, size_t la, const char *b, size_t lb)
{
    while (la > 1 && *a == '0') { a++; la--; }
    while (lb > 1 && *b == '0') { b++; lb--; }

    if (la != lb)
        return la < lb ? -1 : 1;
    int c = memcmp(a, b, la);
    return (c > 0) - (c < 0);
}

static int compare_alpha(const char *a, size_t la, const char *b, size_t lb)
{
    size_t n = la < lb ? la : lb;
    int c = memcmp(a, b, n);
    if (c != 0)
        return (c > 0) - (c < 0);
    if (la != lb)
        return la < lb ? -1 : 1;
    return 0;
}

int version_compare(const char *a, const char *b)
{
    while (*a || *b) {
        while (is_separator(*a)) a++;
        while (is_separator(*b)) b++;

        /* '~' sorts before anything, including the end of the string. */
        if (*a == '~' || *b == '~') {
            if (*a != '~') return 1;
            if (*b != '~') return -1;
            a++;
            b++;
            continue;
        }
        if (*a == '\0' || *b == '\0')
            break;

        const char *sa = a, *sb = b;
        int numeric = isdigit((unsigned char)*a);

        if (numeric) {
            while (isdigit((unsigned char)*a)) a++;
            while (isdigit((unsigned char)*b)) b++;
        } else {
            while (isalpha((unsigned char)*a)) a++;
            while (isalpha((unsigned char)*b)) b++;
        }

        size_t la = (size_t)(a - sa), lb = (size_t)(b - sb);

        /* Run types differ: a numeric run is considered newer. */
        if (lb == 0)
            return numeric ? 1 : -1;

        int c = numeric ? compare_numeric(sa, la, sb, lb)
                        : compare_alpha(sa, la, sb, lb);
        if (c != 0)
            return c;
    }

    if (*a == '\0' && *b == '\0')
        return 0;
    return *a ? 1 : -1;
}

int version_is_valid(const char *v)
{
    if (v == NULL || !isdigit((unsigned char)v[0]))
        return 0;

    size_t len = strlen(v);
    if (len >= 32)
        return 0;

    char prev = '\0';
    for (const char *p = v; *p; p++) {
        char c = *p;
        int sep = (c == '.' || c == '-' || c == '_' || c == '+');
        if (!isalnum((unsigned char)c) && !sep && c != '~')
            return 0;
        if (sep && (prev == '.' || prev == '-' || prev == '_' || prev == '+'))
            return 0; /* empty component such as "1..2" */
        prev = c;
    }
    /* must not end with a separator */
    return !(prev == '.' || prev == '-' || prev == '_' || prev == '+');
}
