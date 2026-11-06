/*
 * patch_manager.h - unified-diff parsing, compatibility checks,
 * simulated application and rollback of security patches.
 *
 * Patch index (data/patches.txt):
 *     patch_id | cve_id | package | upstream_version | patch_file | applied
 *
 *   upstream_version  version the fix was originally written for
 *   patch_file        unified diff in data/patches/
 *   applied           0/1, updated by `patch apply` / `patch revert`
 *
 * Patches are checked against the source tree of the *installed* version
 * (data/sources/<package>-<version>/) and applied only to a sandbox copy
 * (data/sandbox/<package>-<version>/). Original sources are never modified.
 */
#ifndef LG_PATCH_MANAGER_H
#define LG_PATCH_MANAGER_H

#include <stdio.h>
#include "common.h"

/* ------------------------------------------------------------ patch index */

typedef struct {
    char patch_id[LG_ID_MAX];
    char cve_id[LG_ID_MAX];
    char package_name[LG_NAME_MAX];
    char upstream_version[LG_VERSION_MAX];
    char patch_file[128];
    int applied;
} SecurityPatch;

typedef struct {
    SecurityPatch *items;
    size_t count;
    size_t capacity;
} PatchDB;

void patchdb_init(PatchDB *db);
void patchdb_free(PatchDB *db);
lg_status patchdb_load(PatchDB *db, const char *path, int *bad_line);
lg_status patchdb_save(const PatchDB *db, const char *path);
SecurityPatch *patchdb_find(const PatchDB *db, const char *patch_id);

/* ------------------------------------------------------- unified diff model */

typedef struct {
    char type;   /* ' ' context, '-' removed, '+' added */
    char *text;  /* line without the leading type character, no newline */
} DiffLine;

typedef struct {
    int old_start, old_count;
    int new_start, new_count;
    char section[128];   /* text after the second "@@" (function context) */
    DiffLine *lines;
    size_t count, capacity;
} Hunk;

typedef struct {
    char path[LG_PATH_MAX];  /* path with the a/ b/ prefix stripped */
    Hunk *hunks;
    size_t count, capacity;
} FileDiff;

typedef struct {
    FileDiff *files;
    size_t count, capacity;
} Diff;

lg_status diff_parse_stream(FILE *f, Diff *diff, int *bad_line);
lg_status diff_parse_file(const char *path, Diff *diff, int *bad_line);
void diff_free(Diff *diff);

/* ---------------------------------------------------------- text buffers */

typedef struct {
    char **lines;
    size_t count, capacity;
} TextFile;

lg_status text_load(TextFile *tf, const char *path);
lg_status text_save(const TextFile *tf, const char *path);
void text_free(TextFile *tf);

/* -------------------------------------------------------- hunk placement */

typedef enum {
    HUNK_CLEAN,            /* matches exactly at the expected line         */
    HUNK_OFFSET,           /* matches exactly, but at another line         */
    HUNK_FUZZ,             /* matches only when whitespace is ignored      */
    HUNK_ALREADY_APPLIED,  /* the "after" side is already in the file      */
    HUNK_FAILED            /* context not found                            */
} HunkStatus;

typedef struct {
    HunkStatus status;
    size_t at;          /* 0-based line where the hunk matched              */
    long offset;        /* at - expected position                           */
    /* diagnostics for HUNK_FAILED: closest partial match */
    size_t best_at;
    size_t best_matched, needed;
    long first_mismatch; /* index into the hunk's old-side lines, -1 if none */
} HunkResult;

const char *hunk_status_name(HunkStatus s);

/* Find where the hunk applies. reverse=1 looks for the "after" side
 * (used for rollback). */
HunkResult hunk_locate(const TextFile *tf, const Hunk *h, int reverse);

/* Replace the matched side of the hunk at line `at` with the other side. */
lg_status hunk_apply(TextFile *tf, const Hunk *h, size_t at, int reverse);

/* ------------------------------------------------------ patch operations */

typedef struct {
    const char *source_root;   /* data/sources/<pkg>-<ver>  (read-only)  */
    const char *sandbox_root;  /* data/sandbox/<pkg>-<ver>  (writable)   */
} PatchTarget;

typedef struct {
    size_t files, files_missing, files_relocated;
    size_t hunks, clean, offset, fuzz, already, failed;
} PatchCheckSummary;

typedef enum {
    VERDICT_APPLIES_CLEANLY,
    VERDICT_APPLIES_WITH_OFFSET, /* offsets/fuzz, still applicable */
    VERDICT_ALREADY_APPLIED,
    VERDICT_CONFLICT
} PatchVerdict;

const char *patch_verdict_name(PatchVerdict v);
PatchVerdict patch_verdict(const PatchCheckSummary *s);

/*
 * Resolve the file a diff refers to inside the target tree.
 * Prefers the sandbox copy (earlier patches applied), then the original
 * source. If the path doesn't exist, searches for the same file name
 * elsewhere in the tree (files are often moved between releases).
 * rel_out receives the path relative to the tree that was actually used.
 * Returns LG_ERR_NOT_FOUND if the file can't be located.
 */
lg_status patch_resolve_file(const PatchTarget *t, const char *rel,
                             char *abs_out, size_t abs_size,
                             char *rel_out, size_t rel_size,
                             int *relocated);

/* Dry run: report how every hunk of the diff fits the target tree. */
PatchVerdict patch_check(const Diff *diff, const PatchTarget *t,
                         FILE *out, PatchCheckSummary *summary);

/* Apply (reverse=0) or roll back (reverse=1) the diff in the sandbox.
 * All-or-nothing: nothing is written if any hunk fails. */
lg_status patch_apply(const Diff *diff, const PatchTarget *t,
                      int reverse, FILE *out);

#endif /* LG_PATCH_MANAGER_H */
