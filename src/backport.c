#include "backport.h"
#include "diagnostics.h"
#include "logger.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

const char *backport_verdict_name(BackportVerdict v)
{
    switch (v) {
    case BACKPORT_AS_IS:        return "BACKPORTABLE AS-IS";
    case BACKPORT_WITH_CHANGES: return "BACKPORTABLE WITH CHANGES";
    case BACKPORT_MANUAL:       return "MANUAL BACKPORT REQUIRED";
    }
    return "?";
}

/* ------------------------------------------------------------ C tokens */

static int is_ident_start(char c) { return isalpha((unsigned char)c) || c == '_'; }
static int is_ident_char(char c)  { return isalnum((unsigned char)c) || c == '_'; }

static int is_c_keyword(const char *s)
{
    static const char *kw[] = {
        "if", "for", "while", "switch", "return", "sizeof", "do", "else",
        "case", "defined", "_Alignof", "_Generic", "__attribute__", NULL
    };
    for (size_t i = 0; kw[i]; i++)
        if (strcmp(s, kw[i]) == 0)
            return 1;
    return 0;
}

/* Blank out string/char literals and comments so their contents are not
 * mistaken for code. Works on a single line (good enough for diff lines). */
static void strip_noise(const char *in, char *out, size_t size)
{
    size_t o = 0;
    char quote = 0;
    int in_block = 0;

    for (size_t i = 0; in[i] && o + 1 < size; i++) {
        char c = in[i];
        if (in_block) {
            if (c == '*' && in[i + 1] == '/') { in_block = 0; i++; }
            out[o++] = ' ';
        } else if (quote) {
            if (c == '\\' && in[i + 1]) { i++; out[o++] = ' '; }
            else if (c == quote) quote = 0;
            out[o++] = ' ';
        } else if (c == '/' && in[i + 1] == '/') {
            break;
        } else if (c == '/' && in[i + 1] == '*') {
            in_block = 1;
            i++;
            out[o++] = ' ';
        } else if (c == '"' || c == '\'') {
            quote = c;
            out[o++] = ' ';
        } else {
            out[o++] = c;
        }
    }
    out[o] = '\0';
}

/* Calls each identifier on the line; `called` is 1 when it is followed by '('. */
typedef void (*ident_fn)(const char *name, int called, void *ctx);

static void for_each_ident(const char *line, ident_fn fn, void *ctx)
{
    char clean[LG_LINE_MAX];
    strip_noise(line, clean, sizeof clean);

    const char *p = clean;
    while (*p) {
        if (!is_ident_start(*p) || (p > clean && is_ident_char(p[-1]))) {
            p++;
            continue;
        }
        const char *start = p;
        while (is_ident_char(*p))
            p++;
        size_t len = (size_t)(p - start);
        if (len >= LG_NAME_MAX)
            continue;

        char name[LG_NAME_MAX];
        memcpy(name, start, len);
        name[len] = '\0';

        const char *q = p;
        while (*q == ' ' || *q == '\t')
            q++;
        fn(name, *q == '(', ctx);
    }
}

int backport_section_function(const char *section, char *out, size_t size)
{
    const char *paren = strchr(section, '(');
    if (!paren)
        return 0;
    const char *end = paren;
    while (end > section && isspace((unsigned char)end[-1]))
        end--;
    const char *start = end;
    while (start > section && is_ident_char(start[-1]))
        start--;
    if (start == end || !is_ident_start(*start) || (size_t)(end - start) >= size)
        return 0;
    memcpy(out, start, (size_t)(end - start));
    out[end - start] = '\0';
    return !is_c_keyword(out);
}

/* ------------------------------------------------- symbol set helpers */

typedef struct {
    char (*names)[LG_NAME_MAX];
    size_t count, max;
} NameSet;

static int nameset_has(const NameSet *s, const char *name)
{
    for (size_t i = 0; i < s->count; i++)
        if (strcmp(s->names[i], name) == 0)
            return 1;
    return 0;
}

static void nameset_add(NameSet *s, const char *name)
{
    if (s->count < s->max && !nameset_has(s, name))
        lg_strlcpy(s->names[s->count++], name, LG_NAME_MAX);
}

static void collect_any(const char *name, int called, void *ctx)
{
    (void)called;
    nameset_add(ctx, name);
}

static void collect_called(const char *name, int called, void *ctx)
{
    if (called && !is_c_keyword(name))
        nameset_add(ctx, name);
}

size_t backport_added_calls(const Diff *diff, BackportSymbol *out, size_t max)
{
    char existing_buf[512][LG_NAME_MAX];
    char added_buf[BP_MAX_SYMBOLS][LG_NAME_MAX];
    char defined_buf[BP_MAX_SYMBOLS][LG_NAME_MAX];
    NameSet existing = { existing_buf, 0, 512 };
    NameSet added = { added_buf, 0, BP_MAX_SYMBOLS };
    NameSet defined = { defined_buf, 0, BP_MAX_SYMBOLS };

    for (size_t i = 0; i < diff->count; i++) {
        const FileDiff *fd = &diff->files[i];
        for (size_t j = 0; j < fd->count; j++) {
            const Hunk *h = &fd->hunks[j];
            for (size_t k = 0; k < h->count; k++) {
                const DiffLine *l = &h->lines[k];
                if (l->type != '+') {
                    for_each_ident(l->text, collect_any, &existing);
                    continue;
                }
                /* A function definition added by the patch itself
                 * (starts at column 0, no trailing ';') is not a dependency. */
                size_t len = strlen(l->text);
                if (len && !isspace((unsigned char)l->text[0]) &&
                    l->text[0] != '#' && l->text[len - 1] != ';') {
                    char fn[LG_NAME_MAX];
                    if (backport_section_function(l->text, fn, sizeof fn))
                        nameset_add(&defined, fn);
                }
                for_each_ident(l->text, collect_called, &added);
            }
        }
    }

    size_t n = 0;
    for (size_t i = 0; i < added.count && n < max; i++) {
        if (nameset_has(&existing, added.names[i]) ||
            nameset_has(&defined, added.names[i]))
            continue;
        memset(&out[n], 0, sizeof out[n]);
        lg_strlcpy(out[n].name, added.names[i], sizeof out[n].name);
        n++;
    }
    return n;
}

/* --------------------------------------------- search the target tree */

typedef struct {
    BackportSymbol *syms;
    size_t count;
    size_t root_len;
} SymbolSearch;

static int has_source_ext(const char *path)
{
    const char *dot = strrchr(path, '.');
    return dot && (strcmp(dot, ".c") == 0 || strcmp(dot, ".h") == 0);
}

/* Is `name` used as  name(  or  name (  somewhere in buf? */
static int buf_has_call(const char *buf, const char *name)
{
    size_t len = strlen(name);
    for (const char *p = strstr(buf, name); p; p = strstr(p + 1, name)) {
        if (p > buf && is_ident_char(p[-1]))
            continue;
        const char *q = p + len;
        if (is_ident_char(*q))
            continue;
        while (*q == ' ' || *q == '\t')
            q++;
        if (*q == '(')
            return 1;
    }
    return 0;
}

static char *read_whole_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    char *buf = NULL;
    if (fseek(f, 0, SEEK_END) == 0) {
        long size = ftell(f);
        if (size >= 0 && fseek(f, 0, SEEK_SET) == 0 &&
            (buf = malloc((size_t)size + 1)) != NULL) {
            size_t got = fread(buf, 1, (size_t)size, f);
            buf[got] = '\0';
        }
    }
    fclose(f);
    return buf;
}

static int search_visit(const char *path, void *vctx)
{
    SymbolSearch *ctx = vctx;
    if (!has_source_ext(path))
        return 0;

    char *buf = read_whole_file(path);
    if (!buf)
        return 0;

    size_t left = 0;
    for (size_t i = 0; i < ctx->count; i++) {
        BackportSymbol *s = &ctx->syms[i];
        if (!s->found && buf_has_call(buf, s->name)) {
            s->found = 1;
            lg_strlcpy(s->found_in, path + ctx->root_len + 1,
                       sizeof s->found_in);
        }
        if (!s->found)
            left++;
    }
    free(buf);
    return left == 0; /* stop walking once everything is found */
}

static void search_tree(const char *root, BackportSymbol *syms, size_t n)
{
    SymbolSearch ctx = { syms, n, strlen(root) };
    if (n)
        diag_walk(root, search_visit, &ctx);
}

/* --------------------------------------------------------- API map */

static void apply_api_map(const char *path, BackportSymbol *apis, size_t n)
{
    FILE *f = path ? fopen(path, "r") : NULL;
    if (!f)
        return;

    char line[LG_LINE_MAX];
    while (fgets(line, sizeof line, f)) {
        if (lg_is_blank_or_comment(line))
            continue;
        char *fld[3];
        if (lg_split(line, '|', fld, 3) != 3)
            continue;
        for (size_t i = 0; i < n; i++) {
            if (strcmp(apis[i].name, fld[0]) == 0) {
                lg_strlcpy(apis[i].replacement, fld[1], sizeof apis[i].replacement);
                lg_strlcpy(apis[i].note, fld[2], sizeof apis[i].note);
            }
        }
    }
    fclose(f);
}

/* ----------------------------------------------------------- analyze */

lg_status backport_analyze(const Diff *diff, const PatchTarget *target,
                           const char *api_map_path, FILE *out,
                           BackportReport *rep)
{
    memset(rep, 0, sizeof *rep);

    /* 1. parsed upstream patch */
    size_t hunks = 0;
    for (size_t i = 0; i < diff->count; i++)
        hunks += diff->files[i].count;
    if (out)
        fprintf(out, "[1/7] Upstream patch: %zu file(s), %zu hunk(s)\n\n",
                diff->count, hunks);

    /* 2. changed files and functions */
    if (out)
        fprintf(out, "[2/7] Changed files and functions\n");
    for (size_t i = 0; i < diff->count; i++) {
        const FileDiff *fd = &diff->files[i];
        if (out)
            fprintf(out, "      %s:", fd->path);
        for (size_t j = 0; j < fd->count; j++) {
            char fn[LG_NAME_MAX];
            if (!backport_section_function(fd->hunks[j].section, fn, sizeof fn))
                continue;
            int dup = 0;
            for (size_t k = 0; k < rep->function_count; k++)
                if (strcmp(rep->functions[k].name, fn) == 0)
                    dup = 1;
            if (dup || rep->function_count >= BP_MAX_SYMBOLS)
                continue;
            lg_strlcpy(rep->functions[rep->function_count++].name, fn,
                       LG_NAME_MAX);
            if (out)
                fprintf(out, " %s()", fn);
        }
        if (out)
            fputc('\n', out);
    }

    /* 3. do those functions exist in the old release? */
    search_tree(target->source_root, rep->functions, rep->function_count);
    if (out)
        fprintf(out, "\n[3/7] Functions in target version\n");
    for (size_t i = 0; i < rep->function_count; i++) {
        const BackportSymbol *s = &rep->functions[i];
        if (!s->found)
            rep->missing_functions++;
        if (out)
            fprintf(out, "      %-28s %s %s\n", s->name,
                    s->found ? "found in" : "MISSING", s->found_in);
    }

    /* 4. hunk context */
    if (out)
        fprintf(out, "\n[4/7] Context check against target sources\n");
    rep->check_verdict = patch_check(diff, target, out, &rep->check);

    /* 5. new API dependencies */
    rep->api_count = backport_added_calls(diff, rep->apis, BP_MAX_SYMBOLS);
    search_tree(target->source_root, rep->apis, rep->api_count);
    apply_api_map(api_map_path, rep->apis, rep->api_count);

    if (out)
        fprintf(out, "\n[5/7] APIs introduced by the fix\n");
    if (out && rep->api_count == 0)
        fprintf(out, "      (none - the fix only uses code already present)\n");
    for (size_t i = 0; i < rep->api_count; i++) {
        const BackportSymbol *s = &rep->apis[i];
        if (!s->found) {
            rep->missing_apis++;
            if (s->replacement[0] == '\0')
                rep->missing_apis_unmapped++;
        }
        if (!out)
            continue;
        if (s->found)
            fprintf(out, "      %-28s available (%s)\n", s->name, s->found_in);
        else if (s->replacement[0])
            fprintf(out, "      %-28s NOT AVAILABLE -> use %s\n",
                    s->name, s->replacement);
        else
            fprintf(out, "      %-28s NOT AVAILABLE, no known equivalent\n",
                    s->name);
    }

    /* 6. verdict */
    if (rep->check_verdict == VERDICT_CONFLICT || rep->missing_functions ||
        rep->missing_apis_unmapped)
        rep->verdict = BACKPORT_MANUAL;
    else if (rep->missing_apis || rep->check_verdict == VERDICT_APPLIES_WITH_OFFSET)
        rep->verdict = BACKPORT_WITH_CHANGES;
    else
        rep->verdict = BACKPORT_AS_IS;

    if (out) {
        fprintf(out, "\n[6/7] Verdict: %s\n", backport_verdict_name(rep->verdict));
        fprintf(out, "      hunks: %zu ok, %zu offset, %zu fuzz, %zu already "
                     "applied, %zu failed; missing APIs: %zu\n",
                rep->check.clean, rep->check.offset, rep->check.fuzz,
                rep->check.already, rep->check.failed, rep->missing_apis);
    }

    /* 7. how to resolve */
    if (out) {
        fprintf(out, "\n[7/7] Suggested resolution\n");
        int n = 0;
        if (rep->check_verdict == VERDICT_ALREADY_APPLIED)
            fprintf(out, "      %d. The fix is already present in this tree; "
                         "nothing to backport.\n", ++n);
        if (rep->check.files_relocated)
            fprintf(out, "      %d. Rewrite file paths in the patch to the "
                         "locations used by the old release.\n", ++n);
        if (rep->check.failed)
            fprintf(out, "      %d. Re-create the failed hunk(s) by hand on "
                         "top of the old code (see the closest match above).\n",
                    ++n);
        for (size_t i = 0; i < rep->function_count; i++)
            if (!rep->functions[i].found)
                fprintf(out, "      %d. %s() does not exist here: find where the "
                             "vulnerable logic lives in this release, or confirm "
                             "the bug is not present.\n",
                        ++n, rep->functions[i].name);
        for (size_t i = 0; i < rep->api_count; i++) {
            const BackportSymbol *s = &rep->apis[i];
            if (s->found)
                continue;
            if (s->replacement[0])
                fprintf(out, "      %d. Replace %s with %s. %s\n",
                        ++n, s->name, s->replacement, s->note);
            else
                fprintf(out, "      %d. %s is missing: add a compatibility "
                             "shim or rewrite the call with older APIs.\n",
                        ++n, s->name);
        }
        if (n == 0)
            fprintf(out, "      1. No changes needed. Run `legacyguard patch "
                         "apply` to apply it in the sandbox.\n");
    }

    log_msg(LOG_INFO, "Backport analysis: %s", backport_verdict_name(rep->verdict));
    return LG_OK;
}
