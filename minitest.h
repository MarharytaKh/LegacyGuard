/*
 * minitest.h - tiny dependency-free unit test helpers.
 *
 *   TEST(name) { CHECK(expr); CHECK_EQ_INT(a, b); CHECK_EQ_STR(a, b); }
 *   int main(void) { RUN(name); return TEST_REPORT("suite"); }
 */
#ifndef MINITEST_H
#define MINITEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int mt_checks, mt_failures, mt_test_failed;

#define TEST(name) static void name(void)

#define CHECK(expr)                                                         \
    do {                                                                    \
        mt_checks++;                                                        \
        if (!(expr)) {                                                      \
            mt_failures++;                                                  \
            mt_test_failed = 1;                                             \
            fprintf(stderr, "    FAIL %s:%d: %s\n", __FILE__, __LINE__,     \
                    #expr);                                                 \
        }                                                                   \
    } while (0)

#define CHECK_EQ_INT(a, b)                                                  \
    do {                                                                    \
        long long mt_a = (long long)(a), mt_b = (long long)(b);             \
        mt_checks++;                                                        \
        if (mt_a != mt_b) {                                                 \
            mt_failures++;                                                  \
            mt_test_failed = 1;                                             \
            fprintf(stderr, "    FAIL %s:%d: %s == %s (%lld != %lld)\n",    \
                    __FILE__, __LINE__, #a, #b, mt_a, mt_b);                \
        }                                                                   \
    } while (0)

#define CHECK_EQ_STR(a, b)                                                  \
    do {                                                                    \
        const char *mt_a = (a), *mt_b = (b);                                \
        mt_checks++;                                                        \
        if (strcmp(mt_a, mt_b) != 0) {                                      \
            mt_failures++;                                                  \
            mt_test_failed = 1;                                             \
            fprintf(stderr, "    FAIL %s:%d: %s == %s (\"%s\" != \"%s\")\n",\
                    __FILE__, __LINE__, #a, #b, mt_a, mt_b);                \
        }                                                                   \
    } while (0)

#define RUN(test)                                                           \
    do {                                                                    \
        mt_test_failed = 0;                                                 \
        test();                                                             \
        printf("  %s %s\n", mt_test_failed ? "FAIL" : "ok  ", #test);       \
    } while (0)

#define TEST_REPORT(suite)                                                  \
    (printf("%s: %d checks, %d failed\n\n", (suite), mt_checks,             \
            mt_failures),                                                   \
     mt_failures ? 1 : 0)

/* Write text to path (helper for fixtures). Returns 0 on success. */
static inline int mt_write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;
    fputs(text, f);
    return fclose(f);
}

/* Create a fresh temporary directory; returns a static buffer. */
static inline const char *mt_tempdir(void)
{
    static char dir[64];
    strcpy(dir, "/tmp/legacyguard-test-XXXXXX");
    return mkdtemp(dir);
}

/* rm -rf for test cleanup (uses fork/exec via system for brevity). */
static inline void mt_rmtree(const char *dir)
{
    char cmd[256];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
    if (system(cmd) != 0)
        fprintf(stderr, "    warning: could not remove %s\n", dir);
}

#endif /* MINITEST_H */
