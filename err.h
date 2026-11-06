/*
 * Simplified training copy (LegacyGuard test data).
 */
#ifndef HEADER_ERR_H
#define HEADER_ERR_H

#define ERR_LIB_BUF 7

#define ERR_R_MALLOC_FAILURE           65
#define ERR_R_PASSED_NULL_PARAMETER    67
#define ERR_R_PASSED_INVALID_ARGUMENT  7

void ERR_put_error(int lib, int func, int reason, const char *file, int line);
#define ERR_PUT_error(l, f, r, fn, ln) ERR_put_error(l, f, r, fn, ln)

#endif
