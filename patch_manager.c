#include "patch_manager.h"
#include "diagnostics.h"
#include "logger.h"
#include "version.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/* =================================================================
 * Patch index
 * ================================================================= */

void patchdb_init(PatchDB *db)
{
    db->items = NULL;
    db->count = 0;
    db->capacity = 0;
}

void patchdb_free(PatchDB *db)
{
    free(db->items);
    patchdb_init(db);
}

SecurityPatch *patchdb_find(const PatchDB *db, const char *patch_id)
{
    for (size_t i = 0; i < db->count; i++)
        if (strcmp(db->items[i].patch_id, patch_id) == 0)
            return &db->items[i];
    return NULL;
}

lg_status patchdb_load(PatchDB *db, const char *path, int *bad_line)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return LG_ERR_IO;

    char line[LG_LINE_MAX];
    int lineno = 0;
    lg_status st = LG_OK;

    while (fgets(line, sizeof line, f)) {
        lineno++;
        if (lg_is_blank_or_comment(line))
            continue;

        char *fld[6];
        if (lg_split(line, '|', fld, 6) != 6 || !version_is_valid(fld[3]) ||
            (strcmp(fld[5], "0") != 0 && strcmp(fld[5], "1") != 0) ||
            strstr(fld[4], "..") != NULL) {
            st = LG_ERR_FORMAT;
        } else if (patchdb_find(db, fld[0])) {
            st = LG_ERR_EXISTS;
        } else {
            if (db->count == db->capacity) {
                size_t cap = db->capacity ? db->capacity * 2 : 8;
                SecurityPatch *items = realloc(db->items, cap * sizeof *items);
                if (!items) {
                    st = LG_ERR_NOMEM;
                    break;
                }
                db->items = items;
                db->capacity = cap;
            }
            SecurityPatch *p = &db->items[db->count++];
            lg_strlcpy(p->patch_id, fld[0], sizeof p->patch_id);
            lg_strlcpy(p->cve_id, fld[1], sizeof p->cve_id);
            lg_strlcpy(p->package_name, fld[2], sizeof p->package_name);
            lg_strlcpy(p->upstream_version, fld[3], sizeof p->upstream_version);
            lg_strlcpy(p->patch_file, fld[4], sizeof p->patch_file);
            p->applied = fld[5][0] == '1';
        }
        if (st != LG_OK) {
            if (bad_line)
                *bad_line = lineno;
            log_msg(LOG_ERROR, "%s:%d: %s", path, lineno, lg_strerror(st));
            break;
        }
    }
    fclose(f);
    return st;
}

lg_status patchdb_save(const PatchDB *db, const char *path)
{
    char tmp[LG_PATH_MAX + 8];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f)
        return LG_ERR_IO;

    fprintf(f, "# patch_id | cve_id | package | upstream_version | patch_file | applied\n");
    for (size_t i = 0; i < db->count; i++) {
        const SecurityPatch *p = &db->items[i];
        fprintf(f, "%s | %s | %s | %s | %s | %d\n", p->patch_id, p->cve_id,
                p->package_name, p->upstream_version, p->patch_file,
                p->applied);
    }
    if (fclose(f) != 0 || rename(tmp, path) != 0) {
        remove(tmp);
        return LG_ERR_IO;
    }
    return LG_OK;
}

/* =================================================================
 * Unified diff parser
 * ================================================================= */

static void chomp(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r'))
        s[--n] = '\0';
}

/* Make room for one more element. Returns 0 on success, -1 on ENOMEM. */
static int grow(void **arr, size_t count, size_t *cap, size_t elem)
{
    if (count < *cap)
        return 0;
    size_t ncap = *cap ? *cap * 2 : 8;
    void *p = realloc(*arr, ncap * elem);
    if (!p)
        return -1;
    *arr = p;
    *cap = ncap;
    return 0;
}

/* "+++ b/crypto/buffer.c\t2024-01-01 ..." -> "crypto/buffer.c" */
static void parse_diff_path(const char *raw, char *out, size_t out_size)
{
    char tmp[LG_PATH_MAX];
    lg_strlcpy(tmp, raw, sizeof tmp);
    char *tab = strchr(tmp, '\t');
    if (tab)
        *tab = '\0';
    lg_trim(tmp);

    const char *p = tmp;
    if ((p[0] == 'a' || p[0] == 'b') && p[1] == '/')
        p += 2;
    lg_strlcpy(out, p, out_size);
}

/* Parse "-12,7" / "+12" into start and count (count defaults to 1). */
static int parse_range(const char *s, char sign, int *start, int *count)
{
    if (*s != sign)
        return 0;
    char *end;
    long v = strtol(s + 1, &end, 10);
    if (end == s + 1 || v < 0)
        return 0;
    *start = (int)v;
    *count = 1;
    if (*end == ',') {
        const char *c = end + 1;
        long n = strtol(c, &end, 10);
        if (end == c || n < 0)
            return 0;
        *count = (int)n;
    }
    return 1;
}

/* "@@ -84,6 +84,10 @@ int BUF_MEM_grow(...)" */
static int parse_hunk_header(const char *line, Hunk *h)
{
    if (strncmp(line, "@@ ", 3) != 0)
        return 0;
    const char *p = line + 3;
    if (!parse_range(p, '-', &h->old_start, &h->old_count))
        return 0;
    p = strchr(p, ' ');
    if (!p)
        return 0;
    p++;
    if (!parse_range(p, '+', &h->new_start, &h->new_count))
        return 0;
    p = strstr(p, "@@");
    if (!p)
        return 0;
    p += 2;
    while (*p == ' ')
        p++;
    lg_strlcpy(h->section, p, sizeof h->section);
    return 1;
}

static void hunk_free(Hunk *h)
{
    for (size_t i = 0; i < h->count; i++)
        free(h->lines[i].text);
    free(h->lines);
}

void diff_free(Diff *diff)
{
    for (size_t i = 0; i < diff->count; i++) {
        FileDiff *fd = &diff->files[i];
        for (size_t j = 0; j < fd->count; j++)
            hunk_free(&fd->hunks[j]);
        free(fd->hunks);
    }
    free(diff->files);
    diff->files = NULL;
    diff->count = diff->capacity = 0;
}

lg_status diff_parse_stream(FILE *f, Diff *diff, int *bad_line)
{
    diff->files = NULL;
    diff->count = diff->capacity = 0;

    char *line = NULL;
    size_t cap = 0;
    int lineno = 0;
    lg_status st = LG_OK;

    FileDiff *cur_file = NULL;
    Hunk *cur = NULL;
    int old_left = 0, new_left = 0;

    while (getline(&line, &cap, f) != -1) {
        lineno++;
        chomp(line);

        if (cur && (old_left > 0 || new_left > 0)) {
            /* inside a hunk body */
            char type = line[0];
            if (type == '\\')       /* "\ No newline at end of file" */
                continue;
            if (type == '\0')       /* blank context line with stripped space */
                type = ' ';
            if (type != ' ' && type != '-' && type != '+') {
                st = LG_ERR_FORMAT;
                break;
            }
            if ((type != '+' && old_left == 0) || (type != '-' && new_left == 0)) {
                st = LG_ERR_FORMAT; /* more lines than the header announced */
                break;
            }
            if (grow((void **)&cur->lines, cur->count, &cur->capacity, sizeof *cur->lines) != 0) {
                st = LG_ERR_NOMEM;
                break;
            }
            char *text = strdup(line[0] ? line + 1 : "");
            if (!text) {
                st = LG_ERR_NOMEM;
                break;
            }
            cur->lines[cur->count].type = type;
            cur->lines[cur->count].text = text;
            cur->count++;
            if (type != '+') old_left--;
            if (type != '-') new_left--;
            continue;
        }

        if (strncmp(line, "+++ ", 4) == 0) {
            if (grow((void **)&diff->files, diff->count, &diff->capacity, sizeof *diff->files) != 0) {
                st = LG_ERR_NOMEM;
                break;
            }
            cur_file = &diff->files[diff->count++];
            memset(cur_file, 0, sizeof *cur_file);
            parse_diff_path(line + 4, cur_file->path, sizeof cur_file->path);
            cur = NULL;
        } else if (strncmp(line, "@@ ", 3) == 0) {
            if (!cur_file) {
                st = LG_ERR_FORMAT; /* hunk before any file header */
                break;
            }
            if (grow((void **)&cur_file->hunks, cur_file->count, &cur_file->capacity, sizeof *cur_file->hunks) != 0) {
                st = LG_ERR_NOMEM;
                break;
            }
            cur = &cur_file->hunks[cur_file->count++];
            memset(cur, 0, sizeof *cur);
            if (!parse_hunk_header(line, cur)) {
                st = LG_ERR_FORMAT;
                break;
            }
            old_left = cur->old_count;
            new_left = cur->new_count;
        }
        /* anything else ("diff --git", "index", "---", prose) is ignored */
    }

    if (st == LG_OK && cur && (old_left > 0 || new_left > 0))
        st = LG_ERR_FORMAT; /* truncated hunk */
    if (st == LG_OK && diff->count == 0)
        st = LG_ERR_FORMAT; /* not a diff at all */

    free(line);
    if (st != LG_OK) {
        if (bad_line)
            *bad_line = lineno;
        diff_free(diff);
    }
    return st;
}

lg_status diff_parse_file(const char *path, Diff *diff, int *bad_line)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        diff->files = NULL;
        diff->count = diff->capacity = 0;
        return LG_ERR_IO;
    }
    lg_status st = diff_parse_stream(f, diff, bad_line);
    fclose(f);
    return st;
}

/* =================================================================
 * Text buffers
 * ================================================================= */

void text_free(TextFile *tf)
{
    for (size_t i = 0; i < tf->count; i++)
        free(tf->lines[i]);
    free(tf->lines);
    tf->lines = NULL;
    tf->count = tf->capacity = 0;
}

lg_status text_load(TextFile *tf, const char *path)
{
    tf->lines = NULL;
    tf->count = tf->capacity = 0;

    FILE *f = fopen(path, "r");
    if (!f)
        return LG_ERR_IO;

    char *line = NULL;
    size_t cap = 0;
    lg_status st = LG_OK;
    while (getline(&line, &cap, f) != -1) {
        chomp(line);
        if (grow((void **)&tf->lines, tf->count, &tf->capacity, sizeof *tf->lines) != 0) {
                st = LG_ERR_NOMEM;
                break;
            }
        if (!(tf->lines[tf->count] = strdup(line))) {
            st = LG_ERR_NOMEM;
            break;
        }
        tf->count++;
    }
    free(line);
    fclose(f);
    if (st != LG_OK)
        text_free(tf);
    return st;
}

lg_status text_save(const TextFile *tf, const char *path)
{
    char tmp[LG_PATH_MAX * 2 + 8];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f)
        return LG_ERR_IO;
    for (size_t i = 0; i < tf->count; i++)
        fprintf(f, "%s\n", tf->lines[i]);
    if (fclose(f) != 0 || rename(tmp, path) != 0) {
        remove(tmp);
        return LG_ERR_IO;
    }
    return LG_OK;
}

/* =================================================================
 * Hunk placement
 * ================================================================= */

const char *hunk_status_name(HunkStatus s)
{
    switch (s) {
    case HUNK_CLEAN:           return "OK";
    case HUNK_OFFSET:          return "OK (offset)";
    case HUNK_FUZZ:            return "OK (whitespace fuzz)";
    case HUNK_ALREADY_APPLIED: return "ALREADY APPLIED";
    case HUNK_FAILED:          return "FAILED";
    }
    return "?";
}

/* Lines a hunk expects to find ("before" side) or leaves behind ("after"). */
static int is_before_line(char type, int reverse)
{
    return type == ' ' || type == (reverse ? '+' : '-');
}

static int is_after_line(char type, int reverse)
{
    return type == ' ' || type == (reverse ? '-' : '+');
}

/* Compare two lines; in fuzzy mode runs of whitespace are equivalent
 * and leading/trailing whitespace is ignored. */
static int line_equal(const char *a, const char *b, int fuzzy)
{
    if (!fuzzy)
        return strcmp(a, b) == 0;

    while (isspace((unsigned char)*a)) a++;
    while (isspace((unsigned char)*b)) b++;
    while (*a && *b) {
        if (isspace((unsigned char)*a) && isspace((unsigned char)*b)) {
            while (isspace((unsigned char)*a)) a++;
            while (isspace((unsigned char)*b)) b++;
            continue;
        }
        if (*a != *b)
            return 0;
        a++;
        b++;
    }
    while (isspace((unsigned char)*a)) a++;
    while (isspace((unsigned char)*b)) b++;
    return *a == '\0' && *b == '\0';
}

/* Does one side of the hunk match the file at position pos? */
static int side_matches(const TextFile *tf, const Hunk *h, size_t pos,
                        int (*on_side)(char, int), int reverse, int fuzzy)
{
    size_t k = pos;
    for (size_t i = 0; i < h->count; i++) {
        if (!on_side(h->lines[i].type, reverse))
            continue;
        if (k >= tf->count || !line_equal(tf->lines[k], h->lines[i].text, fuzzy))
            return 0;
        k++;
    }
    return 1;
}

static size_t side_len(const Hunk *h, int (*on_side)(char, int), int reverse)
{
    size_t n = 0;
    for (size_t i = 0; i < h->count; i++)
        if (on_side(h->lines[i].type, reverse))
            n++;
    return n;
}

/* Search outward from `expected`: expected, +1, -1, +2, -2, ... */
static int search(const TextFile *tf, const Hunk *h, size_t expected,
                  int (*on_side)(char, int), int reverse, int fuzzy,
                  size_t *found)
{
    size_t n = side_len(h, on_side, reverse);
    if (n > tf->count)
        return 0;
    size_t last = tf->count - n; /* last valid start position */

    for (size_t d = 0; d <= tf->count; d++) {
        if (expected + d <= last &&
            side_matches(tf, h, expected + d, on_side, reverse, fuzzy)) {
            *found = expected + d;
            return 1;
        }
        if (d > 0 && d <= expected && expected - d <= last &&
            side_matches(tf, h, expected - d, on_side, reverse, fuzzy)) {
            *found = expected - d;
            return 1;
        }
    }
    return 0;
}

/*
 * For error reporting: the position that looks most like the intended spot.
 * Ranked by the length of the matching prefix (where the code starts to
 * diverge is what a human needs to see), then by total matching lines.
 */
static void best_partial_match(const TextFile *tf, const Hunk *h, int reverse,
                               HunkResult *r)
{
    size_t best_score = 0;
    r->best_at = 0;
    r->best_matched = 0;
    r->first_mismatch = -1;
    r->needed = side_len(h, is_before_line, reverse);

    for (size_t pos = 0; pos < tf->count; pos++) {
        size_t matched = 0, k = pos;
        long mismatch = -1, idx = 0;
        for (size_t i = 0; i < h->count; i++) {
            if (!is_before_line(h->lines[i].type, reverse))
                continue;
            if (k < tf->count && line_equal(tf->lines[k], h->lines[i].text, 1))
                matched++;
            else if (mismatch < 0)
                mismatch = idx;
            k++;
            idx++;
        }
        size_t prefix = mismatch < 0 ? matched : (size_t)mismatch;
        size_t score = prefix * (r->needed + 1) + matched;
        if (matched > 0 && score > best_score) {
            best_score = score;
            r->best_matched = matched;
            r->best_at = pos;
            r->first_mismatch = mismatch;
        }
    }
}

HunkResult hunk_locate(const TextFile *tf, const Hunk *h, int reverse)
{
    HunkResult r;
    memset(&r, 0, sizeof r);
    r.first_mismatch = -1;

    int start = reverse ? h->new_start : h->old_start;
    int count = reverse ? h->new_count : h->old_count;
    /* With an empty "before" side, start is the line *after* which to insert. */
    size_t expected = count == 0 ? (size_t)start
                                 : (start > 0 ? (size_t)start - 1 : 0);
    if (expected > tf->count)
        expected = tf->count;

    size_t at;
    if (search(tf, h, expected, is_before_line, reverse, 0, &at)) {
        r.status = at == expected ? HUNK_CLEAN : HUNK_OFFSET;
    } else if (search(tf, h, expected, is_before_line, reverse, 1, &at)) {
        r.status = HUNK_FUZZ;
    } else if (side_len(h, is_after_line, reverse) > 0 &&
               search(tf, h, expected, is_after_line, reverse, 1, &at)) {
        r.status = HUNK_ALREADY_APPLIED;
    } else {
        r.status = HUNK_FAILED;
        best_partial_match(tf, h, reverse, &r);
        return r;
    }
    r.at = at;
    r.offset = (long)at - (long)expected;
    return r;
}

lg_status hunk_apply(TextFile *tf, const Hunk *h, size_t at, int reverse)
{
    size_t n_old = side_len(h, is_before_line, reverse);
    size_t n_new = side_len(h, is_after_line, reverse);
    if (at + n_old > tf->count)
        return LG_ERR_CONFLICT;

    size_t new_count = tf->count - n_old + n_new;
    if (new_count > tf->capacity) {
        char **lines = realloc(tf->lines, new_count * sizeof *lines);
        if (!lines)
            return LG_ERR_NOMEM;
        tf->lines = lines;
        tf->capacity = new_count;
    }

    /* Duplicate the replacement first so a failed strdup changes nothing. */
    char **repl = n_new ? malloc(n_new * sizeof *repl) : NULL;
    if (n_new && !repl)
        return LG_ERR_NOMEM;
    size_t r = 0;
    for (size_t i = 0; i < h->count; i++) {
        if (!is_after_line(h->lines[i].type, reverse))
            continue;
        if (!(repl[r] = strdup(h->lines[i].text))) {
            while (r > 0)
                free(repl[--r]);
            free(repl);
            return LG_ERR_NOMEM;
        }
        r++;
    }

    for (size_t i = 0; i < n_old; i++)
        free(tf->lines[at + i]);
    memmove(&tf->lines[at + n_new], &tf->lines[at + n_old],
            (tf->count - at - n_old) * sizeof *tf->lines);
    memcpy(&tf->lines[at], repl, n_new * sizeof *repl);
    tf->count = new_count;
    free(repl);
    return LG_OK;
}

/* =================================================================
 * Patch operations
 * ================================================================= */

const char *patch_verdict_name(PatchVerdict v)
{
    switch (v) {
    case VERDICT_APPLIES_CLEANLY:     return "APPLIES CLEANLY";
    case VERDICT_APPLIES_WITH_OFFSET: return "APPLIES WITH ADJUSTMENTS";
    case VERDICT_ALREADY_APPLIED:     return "ALREADY APPLIED";
    case VERDICT_CONFLICT:            return "CONFLICT";
    }
    return "?";
}

PatchVerdict patch_verdict(const PatchCheckSummary *s)
{
    if (s->files_missing || s->failed)
        return VERDICT_CONFLICT;
    if (s->already == s->hunks && s->hunks > 0)
        return VERDICT_ALREADY_APPLIED;
    if (s->already)
        return VERDICT_CONFLICT; /* partially applied: needs manual review */
    if (s->offset || s->fuzz || s->files_relocated)
        return VERDICT_APPLIES_WITH_OFFSET;
    return VERDICT_APPLIES_CLEANLY;
}

lg_status patch_resolve_file(const PatchTarget *t, const char *rel,
                             char *abs_out, size_t abs_size,
                             char *rel_out, size_t rel_size, int *relocated)
{
    char found[LG_PATH_MAX];
    *relocated = 0;
    lg_strlcpy(found, rel, sizeof found);

    char src[LG_PATH_MAX * 2];
    snprintf(src, sizeof src, "%s/%s", t->source_root, rel);
    if (!diag_is_file(src)) {
        /* File moved between releases? Look for the same name elsewhere. */
        const char *base = strrchr(rel, '/');
        base = base ? base + 1 : rel;
        if (diag_find_file(t->source_root, base, found, sizeof found) != LG_OK)
            return LG_ERR_NOT_FOUND;
        *relocated = 1;
    }

    lg_strlcpy(rel_out, found, rel_size);

    /* Prefer the sandbox copy: it contains previously applied patches. */
    snprintf(abs_out, abs_size, "%s/%s", t->sandbox_root, found);
    if (!diag_is_file(abs_out))
        snprintf(abs_out, abs_size, "%s/%s", t->source_root, found);
    return LG_OK;
}

static void print_hunk_failure(FILE *out, const TextFile *tf, const Hunk *h,
                               const HunkResult *r, int reverse)
{
    if (!out)
        return;
    if (r->best_matched == 0) {
        fprintf(out, "        no part of the hunk context exists in this file\n");
        return;
    }
    fprintf(out, "        closest match at line %zu: %zu/%zu lines agree\n",
            r->best_at + 1, r->best_matched, r->needed);
    if (r->first_mismatch < 0)
        return;

    long idx = 0;
    for (size_t i = 0; i < h->count; i++) {
        if (!is_before_line(h->lines[i].type, reverse))
            continue;
        if (idx == r->first_mismatch) {
            size_t line_no = r->best_at + (size_t)idx;
            fprintf(out, "        expected: %s\n", h->lines[i].text);
            fprintf(out, "        found:    %s\n",
                    line_no < tf->count ? tf->lines[line_no] : "<end of file>");
            return;
        }
        idx++;
    }
}

PatchVerdict patch_check(const Diff *diff, const PatchTarget *t,
                         FILE *out, PatchCheckSummary *s)
{
    memset(s, 0, sizeof *s);

    for (size_t i = 0; i < diff->count; i++) {
        const FileDiff *fd = &diff->files[i];
        char abs[LG_PATH_MAX * 2], rel[LG_PATH_MAX];
        int relocated;

        s->files++;
        s->hunks += fd->count;

        if (patch_resolve_file(t, fd->path, abs, sizeof abs, rel, sizeof rel,
                               &relocated) != LG_OK) {
            s->files_missing++;
            s->failed += fd->count;
            if (out)
                fprintf(out, "  File %s: NOT FOUND in target tree\n", fd->path);
            log_msg(LOG_WARN, "File %s missing in %s", fd->path, t->source_root);
            continue;
        }
        if (relocated) {
            s->files_relocated++;
            if (out)
                fprintf(out, "  File %s -> moved to %s in this version\n",
                        fd->path, rel);
        } else if (out) {
            fprintf(out, "  File %s\n", fd->path);
        }

        TextFile tf;
        if (text_load(&tf, abs) != LG_OK) {
            s->files_missing++;
            s->failed += fd->count;
            if (out)
                fprintf(out, "    cannot read %s\n", abs);
            continue;
        }

        for (size_t j = 0; j < fd->count; j++) {
            const Hunk *h = &fd->hunks[j];
            HunkResult r = hunk_locate(&tf, h, 0);

            switch (r.status) {
            case HUNK_CLEAN:           s->clean++;   break;
            case HUNK_OFFSET:          s->offset++;  break;
            case HUNK_FUZZ:            s->fuzz++;    break;
            case HUNK_ALREADY_APPLIED: s->already++; break;
            case HUNK_FAILED:          s->failed++;  break;
            }

            if (out) {
                fprintf(out, "    hunk %zu  @@ -%d,%d +%d,%d @@ %-28.28s  %s",
                        j + 1, h->old_start, h->old_count, h->new_start,
                        h->new_count, h->section, hunk_status_name(r.status));
                if (r.status == HUNK_OFFSET || r.status == HUNK_FUZZ)
                    fprintf(out, " at line %zu (%+ld)", r.at + 1, r.offset);
                fputc('\n', out);
                if (r.status == HUNK_FAILED)
                    print_hunk_failure(out, &tf, h, &r, 0);
            }
        }
        text_free(&tf);
    }

    PatchVerdict v = patch_verdict(s);
    log_msg(LOG_INFO, "Patch compatibility check: %s (%zu/%zu hunks failed)",
            patch_verdict_name(v), s->failed, s->hunks);
    return v;
}

typedef struct {
    const Hunk *hunk;
    size_t at;
} Placement;

static int placement_cmp(const void *a, const void *b)
{
    const Placement *x = a, *y = b;
    return (x->at > y->at) - (x->at < y->at);
}

lg_status patch_apply(const Diff *diff, const PatchTarget *t,
                      int reverse, FILE *out)
{
    const char *verb = reverse ? "revert" : "apply";
    TextFile *files = calloc(diff->count, sizeof *files);
    char (*rels)[LG_PATH_MAX] = calloc(diff->count, sizeof *rels);
    lg_status st = LG_OK;

    if (!files || !rels) {
        free(files);
        free(rels);
        return LG_ERR_NOMEM;
    }

    /* Phase 1: locate every hunk in every file. Nothing is written yet. */
    for (size_t i = 0; i < diff->count && st == LG_OK; i++) {
        const FileDiff *fd = &diff->files[i];
        char abs[LG_PATH_MAX * 2];
        int relocated;

        if (patch_resolve_file(t, fd->path, abs, sizeof abs, rels[i],
                               sizeof rels[i], &relocated) != LG_OK ||
            text_load(&files[i], abs) != LG_OK) {
            if (out)
                fprintf(out, "  cannot %s: %s not found\n", verb, fd->path);
            st = LG_ERR_NOT_FOUND;
            break;
        }

        Placement *pl = malloc((fd->count ? fd->count : 1) * sizeof *pl);
        if (!pl) {
            st = LG_ERR_NOMEM;
            break;
        }

        for (size_t j = 0; j < fd->count; j++) {
            HunkResult r = hunk_locate(&files[i], &fd->hunks[j], reverse);
            if (r.status == HUNK_FAILED || r.status == HUNK_ALREADY_APPLIED) {
                if (out)
                    fprintf(out, "  cannot %s: %s hunk %zu %s\n", verb,
                            fd->path, j + 1,
                            r.status == HUNK_FAILED
                                ? (reverse ? "does not match (file changed "
                                             "since the patch was applied?)"
                                           : "context not found")
                                : (reverse ? "is not applied"
                                           : "is already applied"));
                st = LG_ERR_CONFLICT;
                break;
            }
            pl[j].hunk = &fd->hunks[j];
            pl[j].at = r.at;
        }

        if (st == LG_OK) {
            /* Apply bottom-up so earlier positions remain valid. */
            qsort(pl, fd->count, sizeof *pl, placement_cmp);
            for (size_t j = 1; j < fd->count; j++) {
                size_t end = pl[j - 1].at +
                             side_len(pl[j - 1].hunk, is_before_line, reverse);
                if (end > pl[j].at) {
                    if (out)
                        fprintf(out, "  cannot %s: overlapping hunks in %s\n",
                                verb, fd->path);
                    st = LG_ERR_CONFLICT;
                    break;
                }
            }
            for (size_t j = fd->count; j-- > 0 && st == LG_OK;)
                st = hunk_apply(&files[i], pl[j].hunk, pl[j].at, reverse);
        }
        free(pl);
    }

    /* Phase 2: all hunks fit - write results into the sandbox. */
    for (size_t i = 0; i < diff->count && st == LG_OK; i++) {
        char dst[LG_PATH_MAX * 2];
        snprintf(dst, sizeof dst, "%s/%s", t->sandbox_root, rels[i]);
        if (diag_make_parent_dirs(dst) != LG_OK ||
            text_save(&files[i], dst) != LG_OK) {
            st = LG_ERR_IO;
            break;
        }
        if (out)
            fprintf(out, "  %s %s\n", reverse ? "restored" : "patched ", dst);
        log_msg(LOG_INFO, "%s %s", reverse ? "Reverted" : "Patched", dst);
    }

    for (size_t i = 0; i < diff->count; i++)
        text_free(&files[i]);
    free(files);
    free(rels);
    return st;
}
