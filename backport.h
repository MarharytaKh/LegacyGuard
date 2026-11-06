/*
 * backport.h - Backport Compatibility Analyzer.
 *
 * Given an upstream fix (unified diff written for a newer release) and the
 * source tree of an older release, decide whether the fix can be carried
 * back as-is, needs adjustments, or must be ported by hand:
 *
 *   1. parse the upstream patch
 *   2. list the changed files and functions
 *   3. check that those functions exist in the old release
 *   4. check the hunk context against the old sources
 *   5. find APIs used by the fix that the old release doesn't have
 *   6. report a verdict
 *   7. suggest how to resolve each conflict by hand
 *
 * Known API renames between releases are read from data/api_map.txt:
 *     new_api | old_equivalent | note
 */
#ifndef LG_BACKPORT_H
#define LG_BACKPORT_H

#include <stdio.h>
#include "common.h"
#include "patch_manager.h"

#define BP_MAX_SYMBOLS 64

typedef enum {
    BACKPORT_AS_IS,          /* applies; nothing missing                    */
    BACKPORT_WITH_CHANGES,   /* applies with offsets / known API renames    */
    BACKPORT_MANUAL          /* context or functions missing, unknown APIs  */
} BackportVerdict;

typedef struct {
    char name[LG_NAME_MAX];
    int found;                     /* present in the target tree          */
    char found_in[LG_PATH_MAX];    /* relative path where it was seen      */
    char replacement[LG_NAME_MAX]; /* from api_map.txt, "" if unknown      */
    char note[LG_DESC_MAX];
} BackportSymbol;

typedef struct {
    PatchCheckSummary check;
    PatchVerdict check_verdict;

    BackportSymbol functions[BP_MAX_SYMBOLS]; /* functions the patch edits */
    size_t function_count;
    BackportSymbol apis[BP_MAX_SYMBOLS];      /* calls added by the patch  */
    size_t api_count;

    size_t missing_functions;
    size_t missing_apis;          /* not in tree                          */
    size_t missing_apis_unmapped; /* not in tree and no known replacement */

    BackportVerdict verdict;
} BackportReport;

const char *backport_verdict_name(BackportVerdict v);

/* Extract the function name from a hunk section such as
 * "int BUF_MEM_grow(BUF_MEM *str, size_t len)". Returns 1 on success. */
int backport_section_function(const char *section, char *out, size_t size);

/* Collect identifiers that are called on '+' lines but never appear on
 * '-' or context lines (i.e. new dependencies introduced by the fix). */
size_t backport_added_calls(const Diff *diff, BackportSymbol *out, size_t max);

lg_status backport_analyze(const Diff *diff, const PatchTarget *target,
                           const char *api_map_path, FILE *out,
                           BackportReport *report);

#endif /* LG_BACKPORT_H */
