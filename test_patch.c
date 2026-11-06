#include "minitest.h"
#include "backport.h"
#include "diagnostics.h"
#include "patch_manager.h"

static const char *SAMPLE_DIFF =
    "diff --git a/src/buf.c b/src/buf.c\n"
    "--- a/src/buf.c\n"
    "+++ b/src/buf.c\n"
    "@@ -3,4 +3,6 @@ int grow(int len)\n"
    " {\n"
    "     int n;\n"
    "+    if (len > LIMIT)\n"
    "+        return report_error(len);\n"
    "     n = len * 2;\n"
    "     return n;\n";

static const char *ORIGINAL =
    "#include \"buf.h\"\n"
    "int grow(int len)\n"
    "{\n"
    "    int n;\n"
    "    n = len * 2;\n"
    "    return n;\n"
    "}\n";

static int parse_text(const char *text, Diff *d)
{
    FILE *f = fmemopen((void *)text, strlen(text), "r");
    int rc = diff_parse_stream(f, d, NULL);
    fclose(f);
    return rc;
}

static void load_lines(TextFile *tf, const char *text)
{
    tf->lines = NULL;
    tf->count = tf->capacity = 0;
    const char *p = text;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (tf->count == tf->capacity) {
            tf->capacity = tf->capacity ? tf->capacity * 2 : 8;
            tf->lines = realloc(tf->lines, tf->capacity * sizeof *tf->lines);
        }
        tf->lines[tf->count] = malloc(len + 1);
        memcpy(tf->lines[tf->count], p, len);
        tf->lines[tf->count][len] = '\0';
        tf->count++;
        p += len + (nl ? 1 : 0);
    }
}

TEST(parse_unified_diff)
{
    Diff d;
    CHECK_EQ_INT(parse_text(SAMPLE_DIFF, &d), LG_OK);
    CHECK_EQ_INT(d.count, 1);
    CHECK_EQ_STR(d.files[0].path, "src/buf.c");
    CHECK_EQ_INT(d.files[0].count, 1);
    Hunk *h = &d.files[0].hunks[0];
    CHECK_EQ_INT(h->old_start, 3);
    CHECK_EQ_INT(h->old_count, 4);
    CHECK_EQ_INT(h->new_count, 6);
    CHECK_EQ_STR(h->section, "int grow(int len)");
    CHECK_EQ_INT(h->count, 6);
    CHECK_EQ_INT(h->lines[2].type, '+');
    diff_free(&d);
}

TEST(reject_malformed_diffs)
{
    Diff d;
    /* hunk shorter than its header claims */
    CHECK_EQ_INT(parse_text("+++ b/x.c\n@@ -1,3 +1,3 @@\n a\n", &d), LG_ERR_FORMAT);
    /* hunk before any file header */
    CHECK_EQ_INT(parse_text("@@ -1 +1 @@\n-a\n+b\n", &d), LG_ERR_FORMAT);
    /* not a diff */
    CHECK_EQ_INT(parse_text("hello\n", &d), LG_ERR_FORMAT);
    /* bad header numbers */
    CHECK_EQ_INT(parse_text("+++ b/x.c\n@@ -x +1 @@\n", &d), LG_ERR_FORMAT);
    /* counts default to 1 */
    CHECK_EQ_INT(parse_text("+++ b/x.c\n@@ -2 +2 @@\n-a\n+b\n", &d), LG_OK);
    CHECK_EQ_INT(d.files[0].hunks[0].old_count, 1);
    diff_free(&d);
}

TEST(locate_clean_offset_fuzz)
{
    Diff d;
    TextFile tf;
    parse_text(SAMPLE_DIFF, &d);
    const Hunk *h = &d.files[0].hunks[0];

    /* header says the hunk starts at line 3, and "{" is on line 3 */
    load_lines(&tf, ORIGINAL);
    HunkResult r = hunk_locate(&tf, h, 0);
    CHECK_EQ_INT(r.status, HUNK_CLEAN);
    CHECK_EQ_INT(r.at, 2);
    text_free(&tf);

    /* code shifted down by 3 lines */
    load_lines(&tf, "a\nb\nc\nd\nint grow(int len)\n{\n    int n;\n    n = len * 2;\n    return n;\n}\n");
    r = hunk_locate(&tf, h, 0);
    CHECK_EQ_INT(r.status, HUNK_OFFSET);
    CHECK_EQ_INT(r.offset, 3);
    text_free(&tf);

    /* different indentation only */
    load_lines(&tf, "{\n\tint n;\n\tn = len * 2;\n\treturn n;\n}\n");
    r = hunk_locate(&tf, h, 0);
    CHECK_EQ_INT(r.status, HUNK_FUZZ);
    text_free(&tf);

    /* real conflict: code changed */
    load_lines(&tf, "{\n    int n;\n    n = len * 4;\n    return n;\n}\n");
    r = hunk_locate(&tf, h, 0);
    CHECK_EQ_INT(r.status, HUNK_FAILED);
    CHECK_EQ_INT(r.best_matched, 3);
    CHECK_EQ_INT(r.first_mismatch, 2);
    text_free(&tf);
    diff_free(&d);
}

TEST(apply_then_reverse_restores_original)
{
    Diff d;
    TextFile tf;
    parse_text(SAMPLE_DIFF, &d);
    const Hunk *h = &d.files[0].hunks[0];
    load_lines(&tf, ORIGINAL);
    size_t original_count = tf.count;

    HunkResult r = hunk_locate(&tf, h, 0);
    CHECK_EQ_INT(hunk_apply(&tf, h, r.at, 0), LG_OK);
    CHECK_EQ_INT(tf.count, original_count + 2);
    CHECK_EQ_STR(tf.lines[4], "    if (len > LIMIT)");

    /* applying again is detected */
    r = hunk_locate(&tf, h, 0);
    CHECK_EQ_INT(r.status, HUNK_ALREADY_APPLIED);

    r = hunk_locate(&tf, h, 1);
    CHECK(r.status == HUNK_CLEAN || r.status == HUNK_OFFSET);
    CHECK_EQ_INT(hunk_apply(&tf, h, r.at, 1), LG_OK);
    CHECK_EQ_INT(tf.count, original_count);
    CHECK_EQ_STR(tf.lines[4], "    n = len * 2;");

    text_free(&tf);
    diff_free(&d);
}

TEST(patch_apply_is_all_or_nothing)
{
    const char *dir = mt_tempdir();
    char src[128], sandbox[128], file[160], out[160];
    snprintf(src, sizeof src, "%s/src", dir);
    snprintf(sandbox, sizeof sandbox, "%s/sandbox", dir);
    snprintf(file, sizeof file, "%s/src/buf.c", dir);
    snprintf(out, sizeof out, "%s/sandbox/src/buf.c", dir);
    diag_make_parent_dirs(file);
    mt_write_file(file, ORIGINAL);

    PatchTarget t = { src, sandbox };
    Diff d;
    parse_text(SAMPLE_DIFF, &d);

    /* the diff path is src/buf.c, but the tree stores it at buf.c... */
    /* ...so patch_resolve_file must find it by name (relocated). */
    char abs[256], rel[128];
    int relocated = 0;
    CHECK_EQ_INT(patch_resolve_file(&t, "src/buf.c", abs, sizeof abs, rel,
                                    sizeof rel, &relocated), LG_OK);
    CHECK_EQ_STR(rel, "buf.c");
    CHECK_EQ_INT(relocated, 1);

    snprintf(out, sizeof out, "%s/sandbox/buf.c", dir);
    CHECK_EQ_INT(patch_apply(&d, &t, 0, NULL), LG_OK);
    CHECK(diag_is_file(out));

    /* original source is untouched */
    TextFile tf;
    CHECK_EQ_INT(text_load(&tf, file), LG_OK);
    CHECK_EQ_INT(tf.count, 7);
    text_free(&tf);

    /* applying twice fails and leaves the sandbox unchanged */
    CHECK_EQ_INT(patch_apply(&d, &t, 0, NULL), LG_ERR_CONFLICT);
    CHECK_EQ_INT(text_load(&tf, out), LG_OK);
    CHECK_EQ_INT(tf.count, 9);
    text_free(&tf);

    /* rollback */
    CHECK_EQ_INT(patch_apply(&d, &t, 1, NULL), LG_OK);
    CHECK_EQ_INT(text_load(&tf, out), LG_OK);
    CHECK_EQ_INT(tf.count, 7);
    text_free(&tf);

    /* check report on a fresh tree */
    PatchCheckSummary s;
    CHECK_EQ_INT(patch_check(&d, &t, NULL, &s), VERDICT_APPLIES_WITH_OFFSET);
    CHECK_EQ_INT(s.files_relocated, 1);

    diff_free(&d);
    mt_rmtree(dir);
}

TEST(two_hunks_apply_bottom_up)
{
    const char *diff =
        "+++ b/f.c\n"
        "@@ -1,2 +1,3 @@\n"
        " a\n"
        "+A\n"
        " b\n"
        "@@ -5,2 +6,3 @@\n"
        " e\n"
        "+E\n"
        " f\n";
    Diff d;
    TextFile tf;
    CHECK_EQ_INT(parse_text(diff, &d), LG_OK);
    load_lines(&tf, "a\nb\nc\nd\ne\nf\n");

    /* locate both on the original, then apply bottom-up like patch_apply */
    HunkResult r1 = hunk_locate(&tf, &d.files[0].hunks[0], 0);
    HunkResult r2 = hunk_locate(&tf, &d.files[0].hunks[1], 0);
    CHECK_EQ_INT(r1.status, HUNK_CLEAN);
    CHECK_EQ_INT(r2.status, HUNK_CLEAN);
    CHECK_EQ_INT(hunk_apply(&tf, &d.files[0].hunks[1], r2.at, 0), LG_OK);
    CHECK_EQ_INT(hunk_apply(&tf, &d.files[0].hunks[0], r1.at, 0), LG_OK);
    CHECK_EQ_INT(tf.count, 8);
    CHECK_EQ_STR(tf.lines[1], "A");
    CHECK_EQ_STR(tf.lines[6], "E");
    text_free(&tf);
    diff_free(&d);
}

TEST(backport_helpers)
{
    char fn[64];
    CHECK(backport_section_function("size_t BUF_MEM_grow(BUF_MEM *str, size_t", fn, sizeof fn));
    CHECK_EQ_STR(fn, "BUF_MEM_grow");
    CHECK(backport_section_function("static int\nfoo (void)", fn, sizeof fn));
    CHECK_EQ_STR(fn, "foo");
    CHECK(!backport_section_function("struct buf_mem_st", fn, sizeof fn));
    CHECK(!backport_section_function("", fn, sizeof fn));

    const char *diff =
        "+++ b/x.c\n"
        "@@ -1,3 +1,9 @@ int f(int a)\n"
        " {\n"
        "+    if (check_len(a) != 0)              /* new API */\n"
        "+        return old_helper(a);          /* already used below */\n"
        "+    log(\"call fake_api(1)\");          /* inside a string */\n"
        "+    return helper2(a);\n"
        "     return old_helper(a);\n"
        " }\n"
        "+static int helper2(int a)\n"
        "+{ return a; }\n";
    Diff d;
    CHECK_EQ_INT(parse_text(diff, &d), LG_OK);
    BackportSymbol syms[8];
    size_t n = backport_added_calls(&d, syms, 8);
    /* check_len and log are new; old_helper exists; helper2 is defined by
     * the patch; fake_api is inside a string literal; if is a keyword */
    CHECK_EQ_INT(n, 2);
    CHECK_EQ_STR(syms[0].name, "check_len");
    CHECK_EQ_STR(syms[1].name, "log");
    diff_free(&d);
}

TEST(run_external_command)
{
    char out[128];
    int code = -1;
    char *ok[] = { "echo", "hello", NULL };
    CHECK_EQ_INT(diag_run_command(ok, out, sizeof out, &code), LG_OK);
    CHECK_EQ_INT(code, 0);
    CHECK_EQ_STR(out, "hello\n");

    char *missing[] = { "legacyguard-no-such-command", NULL };
    CHECK_EQ_INT(diag_run_command(missing, out, sizeof out, &code), LG_OK);
    CHECK_EQ_INT(code, 127);

    /* output larger than the buffer is truncated, not overflowed */
    char small[4];
    char *sh[] = { "printf", "abcdefgh", NULL };
    CHECK_EQ_INT(diag_run_command(sh, small, sizeof small, &code), LG_OK);
    CHECK_EQ_STR(small, "abc");
}

int main(void)
{
    printf("test_patch\n");
    RUN(parse_unified_diff);
    RUN(reject_malformed_diffs);
    RUN(locate_clean_offset_fuzz);
    RUN(apply_then_reverse_restores_original);
    RUN(patch_apply_is_all_or_nothing);
    RUN(two_hunks_apply_bottom_up);
    RUN(backport_helpers);
    RUN(run_external_command);
    return TEST_REPORT("test_patch");
}
