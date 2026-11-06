/*
 * diagnostics.h - Linux system helpers built on POSIX APIs:
 * fork/exec/pipe/waitpid, stat, access, opendir/readdir, mkdir.
 */
#ifndef LG_DIAGNOSTICS_H
#define LG_DIAGNOSTICS_H

#include <stddef.h>
#include "common.h"

/*
 * Run an external program (argv[0] looked up in PATH) in a child process,
 * capturing its stdout+stderr through a pipe into out (NUL-terminated,
 * truncated to out_size-1). Returns LG_OK if the program was started;
 * *exit_code receives its exit status (127 if exec failed).
 */
lg_status diag_run_command(char *const argv[], char *out, size_t out_size,
                           int *exit_code);

/* 1 if path is an existing regular file / directory. */
int diag_is_file(const char *path);
int diag_is_dir(const char *path);

/* Create every missing directory in the parent path of file_path. */
lg_status diag_make_parent_dirs(const char *file_path);

/*
 * Recursively walk root and call visit() for every regular file.
 * Walking stops early when visit() returns non-zero; that value is returned.
 */
typedef int (*diag_visit_fn)(const char *path, void *ctx);
int diag_walk(const char *root, diag_visit_fn visit, void *ctx);

/*
 * Search root recursively for a file whose name equals basename.
 * The path relative to root is stored in found. Returns LG_ERR_NOT_FOUND
 * if nothing matches.
 */
lg_status diag_find_file(const char *root, const char *basename,
                         char *found, size_t found_size);

/* Print the full environment / data-directory diagnostics report. */
int diag_report(const char *data_dir);

#endif /* LG_DIAGNOSTICS_H */
