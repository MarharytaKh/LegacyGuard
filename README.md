# LegacyGuard — Linux Security Patch Manager

A command-line tool in C11 that does, on a small scale, what an Endless
Lifecycle Support team does every day: find which installed packages are
affected by a known vulnerability, take the upstream fix written for a newer
release, and work out whether — and how — it can be **backported** to the old
version that is still in production.

```
openssl 1.1.1k is affected by CVE-TEST-0001.
The fix was written for 3.0.13.
-> the hunks apply with a -3 line offset,
-> but the fix calls ERR_raise(), which 1.1.1 doesn't have,
-> use BUFerr(BUF_F_<FUNCTION>, reason) instead.
```

> **Scope.** LegacyGuard works with a training CVE database and mock source
> trees in `data/`. CVE IDs use the `CVE-TEST-` prefix on purpose. Patches are
> applied only to a sandbox copy (`data/sandbox/`); real system packages and
> the original sources are never modified.

## Features

| Module | File | What it does |
|---|---|---|
| Package Manager | `package_manager.c` | add / remove / update packages, version validation, atomic save (write to `.tmp` + `rename`) |
| Version Comparator | `version.c` | component-wise comparison: `1.2.9 < 1.2.10`, `1.1.1 < 1.1.1k`, `8.0.0~rc1 < 8.0.0`; no integer overflow on long numbers |
| CVE Scanner | `cve_scanner.c` | matches packages against `introduced_in <= v < fixed_in` ranges, report with severity totals |
| Patch Manager | `patch_manager.c` | unified-diff parser, hunk placement with offset search and whitespace fuzz, "already applied" detection, all-or-nothing apply, rollback via reverse apply |
| Backport Analyzer | `backport.c` | changed functions, their presence in the old tree, new API dependencies, known API renames, verdict and manual resolution steps |
| System Diagnostics | `diagnostics.c` | `fork` / `execvp` / `pipe` / `waitpid`, `stat`, `access`, `opendir` / `readdir`, `uname`, recursive tree walk |
| Logging | `logger.c` | timestamped log of every scan, check and patch action |

## Build and run

Requirements: Linux, GCC (or Clang), GNU Make. No external libraries.

```sh
make                 # build ./legacyguard
make test            # unit tests (352 checks)
make asan            # rebuild with AddressSanitizer + UBSan and run the tests
make valgrind        # tests and the full demo under valgrind --leak-check=full
make demo            # end-to-end demo on a temporary copy of data/
```

```
Usage: legacyguard [-d DATA_DIR] [-v] <command> [args]

  list | add <name> <version> <distro> | remove <name> | update <name> <version>
  scan                       check packages against the CVE DB
  compare <v1> <v2>          compare two versions
  patch list                 list known security patches
  patch check  <id>          dry run against the installed version
  patch apply  <id>          apply in the sandbox
  patch revert <id>          roll back from the sandbox
  backport <id>              full backport compatibility analysis
  diag                       environment and data diagnostics
```

Exit status: `0` ok, `1` error, `2` vulnerabilities found or patch conflict,
so the tool can be used as a CI gate.

## Example session

### Scan

```
$ legacyguard scan
...
Package: openssl
Version: 1.1.1k (CentOS 7)

  CVE:      CVE-TEST-0001
  Severity: CRITICAL
  Affected: 1.0.2 <= v < 1.1.1w
  Summary:  Integer overflow in BUF_MEM_grow() size calculation ...

Status: VULNERABLE (1 CVE)
...
Package: curl
Version: 7.29.0 (CentOS 7)

Status: NO KNOWN VULNERABILITIES
----------------------------------------
Total packages:      4
Vulnerable packages: 3
Findings:            3  (critical 1, high 1, medium 1, low 0)

Available patches:
  PATCH-0002     fixes CVE-TEST-0001    in openssl
  PATCH-0002-BP  fixes CVE-TEST-0001    in openssl
  PATCH-0001     fixes CVE-TEST-0003    in php
  PATCH-0003     fixes CVE-TEST-0004    in nginx
```

### Backport analysis: fix needs changes

The upstream fix for OpenSSL 3.0 checked against 1.1.1k:

```
$ legacyguard backport PATCH-0002
Patch:   PATCH-0002  (CVE-TEST-0001)
Written: openssl 3.0.13
Target:  openssl 1.1.1k  [data/sources/openssl-1.1.1k]

[1/7] Upstream patch: 1 file(s), 2 hunk(s)

[2/7] Changed files and functions
      crypto/buffer/buffer.c: BUF_MEM_grow() BUF_MEM_grow_clean()

[3/7] Functions in target version
      BUF_MEM_grow                 found in crypto/buffer/buffer.c
      BUF_MEM_grow_clean           found in crypto/buffer/buffer.c

[4/7] Context check against target sources
  File crypto/buffer/buffer.c
    hunk 1  @@ -86,6 +86,10 @@ size_t BUF_MEM_grow(BUF_MEM   OK (offset) at line 83 (-3)
    hunk 2  @@ -119,6 +123,10 @@ size_t BUF_MEM_grow_clean(BU  OK (offset) at line 116 (-3)

[5/7] APIs introduced by the fix
      ERR_raise                    NOT AVAILABLE -> use BUFerr(BUF_F_<FUNCTION>, reason)

[6/7] Verdict: BACKPORTABLE WITH CHANGES

[7/7] Suggested resolution
      1. Replace ERR_raise with BUFerr(BUF_F_<FUNCTION>, reason). ERR_raise() appeared
         in OpenSSL 3.0; 1.1.1 reports errors through per-library macros with a function code.
```

A plain `patch` would apply this diff "successfully" and produce code that
doesn't compile on 1.1.1. The hand-made backport `PATCH-0002-BP` uses `BUFerr`
and applies cleanly.

### Backport analysis: manual work required

The nginx fix was written after upstream refactored the code:

```
$ legacyguard backport PATCH-0003
[3/7] Functions in target version
      ngx_resolver_copy_name       MISSING

[4/7] Context check against target sources
  File src/core/ngx_resolver.c
    hunk 1  @@ -24,6 +24,11 @@ ngx_resolver_copy_name(ngx_r  FAILED
        closest match at line 29: 3/6 lines agree
        expected:             *out_len = len;
        found:                goto done;
    hunk 2  @@ -33,6 +38,11 @@ ngx_resolver_copy_name(ngx_r  OK (offset) at line 37 (+4)

[5/7] APIs introduced by the fix
      ngx_resolver_check_label     NOT AVAILABLE, no known equivalent

[6/7] Verdict: MANUAL BACKPORT REQUIRED
```

Hunk 2 matches by context, but inside a *different* function
(`ngx_resolver_copy`): exactly the kind of false positive that has to be
caught before shipping a backport.

### Apply, detect, roll back

```
$ legacyguard patch apply PATCH-0002-BP
  patched  data/sandbox/openssl-1.1.1k/crypto/buffer/buffer.c
Applied PATCH-0002-BP in sandbox

$ legacyguard patch check PATCH-0002-BP
    hunk 1  @@ -83,6 +83,10 @@ size_t BUF_MEM_grow(BUF_MEM   ALREADY APPLIED
    hunk 2  @@ -116,6 +120,10 @@ size_t BUF_MEM_grow_clean(BU  ALREADY APPLIED

$ legacyguard patch revert PATCH-0002-BP
  restored data/sandbox/openssl-1.1.1k/crypto/buffer/buffer.c
Reverted PATCH-0002-BP in sandbox

$ legacyguard patch apply PATCH-0003
  cannot apply: src/core/ngx_resolver.c hunk 1 context not found
legacyguard: PATCH-0003 failed, sandbox left unchanged: patch conflict
```

## How patching works

1. **Parse** the unified diff into files → hunks → lines (`' '`, `-`, `+`).
   Truncated hunks, hunks before a file header and bad `@@` headers are rejected.
2. **Resolve** each file in the target tree: sandbox copy first (earlier
   patches stay stacked), then original source; if the path doesn't exist,
   search the tree by file name, since files move between releases.
3. **Locate** every hunk: search outward from the expected line
   (`0, +1, -1, +2, ...`) for an exact match, then a whitespace-insensitive
   one; otherwise test whether the "after" side is already there. For a
   failed hunk, report the position with the longest matching prefix and the
   first differing line.
4. **Apply** all-or-nothing: hunks are located on the unmodified file, checked
   for overlap, applied bottom-up (so earlier line numbers stay valid), and
   files are written only after every hunk in every file fits, each through a
   temporary file + `rename()`.
5. **Revert** is the same algorithm with the sides swapped. If the sandbox
   file was edited after applying, the revert fails instead of corrupting it.

## Data formats

All files are `|`-separated; `#` starts a comment.

| File | Fields |
|---|---|
| `data/packages.txt` | `name \| version \| distribution` |
| `data/vulnerabilities.txt` | `cve_id \| package \| introduced_in (or *) \| fixed_in \| severity \| description` |
| `data/patches.txt` | `patch_id \| cve_id \| package \| upstream_version \| patch_file \| applied` |
| `data/api_map.txt` | `new_api \| old_equivalent \| note` |
| `data/patches/*.patch` | unified diffs (`diff -u` / `git diff`) |
| `data/sources/<pkg>-<version>/` | mock source tree of the installed version |

## Project layout

```
LegacyGuard/
├── src/
│   ├── main.c              CLI
│   ├── common.[ch]         error codes, string helpers
│   ├── version.[ch]        version comparator
│   ├── package_manager.[ch]
│   ├── cve_scanner.[ch]
│   ├── patch_manager.[ch]  diff parser, hunk placement, apply/revert
│   ├── backport.[ch]       backport compatibility analyzer
│   ├── diagnostics.[ch]    fork/exec/pipe, stat/access, opendir/readdir
│   └── logger.[ch]
├── tests/                  test_version.c, test_scanner.c, test_patch.c, minitest.h
├── data/                   training CVE DB, patches, mock source trees
├── scripts/demo.sh         end-to-end demo (also used by `make valgrind`)
├── .github/workflows/ci.yml
└── Makefile
```

## Quality checks

- `-std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wformat=2`: builds with no warnings.
- 352 unit-test checks (version ordering properties, half-open CVE ranges,
  malformed input, offset/fuzz/conflict placement, apply → revert round trip,
  all-or-nothing behaviour, pipe output truncation).
- AddressSanitizer + UndefinedBehaviorSanitizer and Valgrind (`--leak-check=full`)
  run clean on the tests and on every CLI command in the demo.
- `strace -f ./legacyguard diag` shows the `pipe2 → clone → execve → wait4`
  sequence used to run external tools.

## Limitations

- Parses C sources with simple heuristics (identifier followed by `(`); macros
  that expand to calls and function pointers are not resolved.
- Hunks are placed independently; very large offsets are found but may land
  on a repeated code block (the backport analyzer's function check exists to
  catch that).
- No real package-manager integration (`rpm -q` / `dpkg -s`) yet.

## License

MIT, see [LICENSE](LICENSE).
