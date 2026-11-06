/*
 * Simplified training copy (LegacyGuard test data).
 * 1.1.1-era error reporting: one macro per library.
 */
#ifndef HEADER_BUFERR_H
#define HEADER_BUFERR_H

#include <openssl/err.h>

#define BUFerr(f, r) ERR_PUT_error(ERR_LIB_BUF, (f), (r), OPENSSL_FILE, OPENSSL_LINE)

/* function codes */
#define BUF_F_BUF_MEM_GROW        100
#define BUF_F_BUF_MEM_GROW_CLEAN  105
#define BUF_F_BUF_MEM_NEW         101

#endif
