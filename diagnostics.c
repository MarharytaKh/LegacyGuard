#include "diagnostics.h"
#include "logger.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

lg_status diag_run_command(char *const argv[], char *out, size_t out_size,
                           int *exit_code)
{
    int fds[2];
    if (pipe(fds) != 0)
        return LG_ERR_IO;

    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return LG_ERR_IO;
    }

    if (pid == 0) {
        /* child: route stdout and stderr into the pipe, then exec */
        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        dup2(fds[1], STDERR_FILENO);
        close(fds[1]);
        execvp(argv[0], argv);
        _exit(127); /* exec failed: command not found */
    }

    /* parent: read everything the child writes */
    close(fds[1]);
    size_t used = 0;
    char buf[512];
    ssize_t n;
    while ((n = read(fds[0], buf, sizeof buf)) > 0 || (n < 0 && errno == EINTR)) {
        if (n < 0)
            continue;
        if (out && used + 1 < out_size) {
            size_t room = out_size - 1 - used;
            size_t take = (size_t)n < room ? (size_t)n : room;
            memcpy(out + used, buf, take);
            used += take;
        }
    }
    close(fds[0]);
    if (out && out_size)
        out[used] = '\0';

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return LG_ERR_IO;
    }
    if (exit_code)
        *exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return LG_OK;
}

int diag_is_file(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

int diag_is_dir(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

lg_status diag_make_parent_dirs(const char *file_path)
{
    char buf[LG_PATH_MAX * 2];
    lg_strlcpy(buf, file_path, sizeof buf);

    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0755) != 0 && errno != EEXIST)
            return LG_ERR_IO;
        *p = '/';
    }
    return LG_OK;
}

int diag_walk(const char *root, diag_visit_fn visit, void *ctx)
{
    DIR *dir = opendir(root);
    if (!dir)
        return 0;

    int rc = 0;
    struct dirent *de;
    while (rc == 0 && (de = readdir(dir)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        char path[LG_PATH_MAX * 2];
        int len = snprintf(path, sizeof path, "%s/%s", root, de->d_name);
        if (len < 0 || (size_t)len >= sizeof path)
            continue;

        struct stat st;
        if (lstat(path, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode))
            rc = diag_walk(path, visit, ctx);
        else if (S_ISREG(st.st_mode))
            rc = visit(path, ctx);
    }
    closedir(dir);
    return rc;
}

struct find_ctx {
    const char *basename;
    size_t root_len;
    char *found;
    size_t found_size;
};

static int find_visit(const char *path, void *vctx)
{
    struct find_ctx *ctx = vctx;
    const char *slash = strrchr(path, '/');
    const char *name = slash ? slash + 1 : path;
    if (strcmp(name, ctx->basename) != 0)
        return 0;
    lg_strlcpy(ctx->found, path + ctx->root_len + 1, ctx->found_size);
    return 1;
}

lg_status diag_find_file(const char *root, const char *basename,
                         char *found, size_t found_size)
{
    struct find_ctx ctx = { basename, strlen(root), found, found_size };
    return diag_walk(root, find_visit, &ctx) ? LG_OK : LG_ERR_NOT_FOUND;
}

/* ---------------------------------------------------------------- report */

static void report_tool(const char *tool)
{
    char *argv[] = { (char *)tool, "--version", NULL };
    char out[256];
    int code = 0;

    if (diag_run_command(argv, out, sizeof out, &code) != LG_OK || code == 127) {
        printf("  %-10s NOT FOUND\n", tool);
        return;
    }
    char *nl = strchr(out, '\n');
    if (nl)
        *nl = '\0';
    printf("  %-10s %s\n", tool, out);
}

static void report_path(const char *path, int need_write)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        printf("  [MISSING] %s\n", path);
        return;
    }
    char mtime[32];
    struct tm tm_m;
    localtime_r(&st.st_mtime, &tm_m);
    strftime(mtime, sizeof mtime, "%Y-%m-%d %H:%M", &tm_m);

    int r = access(path, R_OK) == 0;
    int w = access(path, W_OK) == 0;
    const char *state = (!r || (need_write && !w)) ? "NO ACCESS" : "OK";

    printf("  [%-9s] %-32s %8lld B  %s  %c%c\n", state, path,
           (long long)st.st_size, mtime, r ? 'r' : '-', w ? 'w' : '-');
}

static int count_visit(const char *path, void *ctx)
{
    (void)path;
    (*(size_t *)ctx)++;
    return 0;
}

int diag_report(const char *data_dir)
{
    struct utsname u;
    printf("System\n");
    if (uname(&u) == 0)
        printf("  %s %s (%s)\n", u.sysname, u.release, u.machine);
    printf("  pid %d, uid %d\n\n", (int)getpid(), (int)getuid());

    printf("Tools (via fork/exec/pipe)\n");
    report_tool("gcc");
    report_tool("make");
    report_tool("patch");
    report_tool("diff");
    report_tool("git");

    char path[LG_PATH_MAX];
    printf("\nData files (stat/access)\n");
    snprintf(path, sizeof path, "%s/packages.txt", data_dir);
    report_path(path, 1);
    snprintf(path, sizeof path, "%s/vulnerabilities.txt", data_dir);
    report_path(path, 0);
    snprintf(path, sizeof path, "%s/patches.txt", data_dir);
    report_path(path, 1);
    snprintf(path, sizeof path, "%s/api_map.txt", data_dir);
    report_path(path, 0);

    printf("\nSource trees (opendir/readdir)\n");
    snprintf(path, sizeof path, "%s/sources", data_dir);
    DIR *dir = opendir(path);
    if (!dir) {
        printf("  [MISSING] %s\n", path);
        log_msg(LOG_WARN, "Source directory %s missing", path);
        return 1;
    }
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.')
            continue;
        char tree[LG_PATH_MAX * 2];
        snprintf(tree, sizeof tree, "%s/%s", path, de->d_name);
        if (!diag_is_dir(tree))
            continue;
        size_t files = 0;
        diag_walk(tree, count_visit, &files);
        printf("  %-28s %zu file(s)\n", de->d_name, files);
    }
    closedir(dir);
    log_msg(LOG_INFO, "Diagnostics completed");
    return 0;
}
