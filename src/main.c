/*
 * LegacyGuard - Linux security patch manager (training tool).
 *
 * Scans installed packages against a CVE database, checks whether
 * security fixes fit older releases, and simulates applying / reverting
 * them in a sandbox copy of the sources.
 */
#include "backport.h"
#include "common.h"
#include "cve_scanner.h"
#include "diagnostics.h"
#include "logger.h"
#include "package_manager.h"
#include "patch_manager.h"
#include "version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define EXIT_FINDINGS 2   /* scan found vulnerabilities / patch conflicts */

static const char *data_dir = "data";

static void usage(FILE *out)
{
    fprintf(out,
        "Usage: legacyguard [-d DATA_DIR] [-v] <command> [args]\n"
        "\n"
        "Packages\n"
        "  list                                 show installed packages\n"
        "  add <name> <version> <distribution>  register a package\n"
        "  remove <name>                        unregister a package\n"
        "  update <name> <version>              change installed version\n"
        "\n"
        "Security\n"
        "  scan                                 check packages against the CVE DB\n"
        "  compare <v1> <v2>                    compare two versions\n"
        "\n"
        "Patches (applied only to DATA_DIR/sandbox, never to real sources)\n"
        "  patch list                           list known security patches\n"
        "  patch check  <patch-id>              dry run: does it fit the installed version?\n"
        "  patch apply  <patch-id>              apply in the sandbox\n"
        "  patch revert <patch-id>              roll back from the sandbox\n"
        "  backport <patch-id>                  full backport compatibility analysis\n"
        "\n"
        "System\n"
        "  diag                                 environment and data diagnostics\n"
        "\n"
        "Exit status: 0 ok, 1 error, 2 vulnerabilities found / patch conflict.\n");
}

static void data_path(char *buf, size_t size, const char *name)
{
    snprintf(buf, size, "%s/%s", data_dir, name);
}

static int fail(const char *what, lg_status st, int line)
{
    if (line > 0)
        fprintf(stderr, "legacyguard: %s (line %d): %s\n", what, line,
                lg_strerror(st));
    else
        fprintf(stderr, "legacyguard: %s: %s\n", what, lg_strerror(st));
    return EXIT_FAILURE;
}

/* ---------------------------------------------------------- packages */

static int load_packages(PackageList *pkgs)
{
    char path[LG_PATH_MAX];
    int line = 0;
    data_path(path, sizeof path, "packages.txt");
    pkglist_init(pkgs);
    lg_status st = pkglist_load(pkgs, path, &line);
    if (st != LG_OK) {
        pkglist_free(pkgs);
        return fail(path, st, line);
    }
    return 0;
}

static int save_packages(const PackageList *pkgs)
{
    char path[LG_PATH_MAX];
    data_path(path, sizeof path, "packages.txt");
    lg_status st = pkglist_save(pkgs, path);
    return st == LG_OK ? 0 : fail(path, st, 0);
}

static int cmd_packages(int argc, char **argv)
{
    PackageList pkgs;
    if (load_packages(&pkgs))
        return EXIT_FAILURE;

    const char *cmd = argv[0];
    lg_status st = LG_OK;
    int rc = 0;

    if (strcmp(cmd, "list") == 0) {
        pkglist_print(&pkgs);
        pkglist_free(&pkgs);
        return 0;
    }

    if (strcmp(cmd, "add") == 0 && argc == 4) {
        st = pkglist_add(&pkgs, argv[1], argv[2], argv[3]);
        if (st == LG_OK)
            log_msg(LOG_INFO, "Package %s %s added", argv[1], argv[2]);
    } else if (strcmp(cmd, "remove") == 0 && argc == 2) {
        st = pkglist_remove(&pkgs, argv[1]);
        if (st == LG_OK)
            log_msg(LOG_INFO, "Package %s removed", argv[1]);
    } else if (strcmp(cmd, "update") == 0 && argc == 3) {
        st = pkglist_set_version(&pkgs, argv[1], argv[2]);
        if (st == LG_OK)
            log_msg(LOG_INFO, "Package %s updated to %s", argv[1], argv[2]);
    } else {
        usage(stderr);
        pkglist_free(&pkgs);
        return EXIT_FAILURE;
    }

    if (st != LG_OK)
        rc = fail(argv[1], st, 0);
    else if ((rc = save_packages(&pkgs)) == 0)
        printf("ok: %s %s\n", cmd, argv[1]);

    pkglist_free(&pkgs);
    return rc;
}

/* -------------------------------------------------------------- scan */

static int load_patches(PatchDB *db)
{
    char path[LG_PATH_MAX];
    int line = 0;
    data_path(path, sizeof path, "patches.txt");
    patchdb_init(db);
    lg_status st = patchdb_load(db, path, &line);
    if (st != LG_OK) {
        patchdb_free(db);
        return fail(path, st, line);
    }
    return 0;
}

static int cmd_scan(void)
{
    PackageList pkgs;
    VulnDB db;
    char path[LG_PATH_MAX];
    int line = 0;

    if (load_packages(&pkgs))
        return EXIT_FAILURE;

    data_path(path, sizeof path, "vulnerabilities.txt");
    vulndb_init(&db);
    lg_status st = vulndb_load(&db, path, &line);
    if (st != LG_OK) {
        pkglist_free(&pkgs);
        vulndb_free(&db);
        return fail(path, st, line);
    }

    log_msg(LOG_INFO, "Security scan started (%zu packages, %zu CVEs)",
            pkgs.count, db.count);
    ScanSummary sum;
    scan_packages(&pkgs, &db, stdout, &sum);

    /* Point to patches that exist for the detected CVEs. */
    PatchDB patches;
    if (sum.findings && load_patches(&patches) == 0) {
        int header = 0;
        for (size_t i = 0; i < pkgs.count; i++)
            for (size_t j = 0; j < db.count; j++) {
                const Vulnerability *v = &db.items[j];
                if (!vuln_affects(v, pkgs.items[i].name, pkgs.items[i].version))
                    continue;
                for (size_t k = 0; k < patches.count; k++) {
                    const SecurityPatch *p = &patches.items[k];
                    if (strcmp(p->cve_id, v->cve_id) != 0)
                        continue;
                    if (!header++)
                        printf("\nAvailable patches:\n");
                    printf("  %-14s fixes %-16s in %s%s\n", p->patch_id,
                           p->cve_id, p->package_name,
                           p->applied ? "  (applied in sandbox)" : "");
                }
            }
        patchdb_free(&patches);
    }

    pkglist_free(&pkgs);
    vulndb_free(&db);
    return sum.vulnerable_packages ? EXIT_FINDINGS : 0;
}

static int cmd_compare(const char *a, const char *b)
{
    if (!version_is_valid(a) || !version_is_valid(b)) {
        fprintf(stderr, "legacyguard: invalid version string\n");
        return EXIT_FAILURE;
    }
    int c = version_compare(a, b);
    printf("%s %s %s\n", a, c < 0 ? "<" : c > 0 ? ">" : "==", b);
    return 0;
}

/* ----------------------------------------------------------- patches */

typedef struct {
    PatchDB db;
    SecurityPatch *patch;
    Diff diff;
    char installed[LG_VERSION_MAX];
    char source_root[LG_PATH_MAX];
    char sandbox_root[LG_PATH_MAX];
    PatchTarget target;
} PatchJob;

static void job_free(PatchJob *job)
{
    diff_free(&job->diff);
    patchdb_free(&job->db);
}

/* Load the patch index, the diff and work out the target source tree. */
static int job_open(PatchJob *job, const char *patch_id)
{
    memset(job, 0, sizeof *job);
    if (load_patches(&job->db))
        return EXIT_FAILURE;

    job->patch = patchdb_find(&job->db, patch_id);
    if (!job->patch) {
        patchdb_free(&job->db);
        return fail(patch_id, LG_ERR_NOT_FOUND, 0);
    }

    PackageList pkgs;
    if (load_packages(&pkgs)) {
        patchdb_free(&job->db);
        return EXIT_FAILURE;
    }
    const Package *pkg = pkglist_find(&pkgs, job->patch->package_name);
    if (!pkg) {
        fprintf(stderr, "legacyguard: package %s is not installed\n",
                job->patch->package_name);
        pkglist_free(&pkgs);
        patchdb_free(&job->db);
        return EXIT_FAILURE;
    }
    lg_strlcpy(job->installed, pkg->version, sizeof job->installed);
    pkglist_free(&pkgs);

    snprintf(job->source_root, sizeof job->source_root, "%s/sources/%s-%s",
             data_dir, job->patch->package_name, job->installed);
    snprintf(job->sandbox_root, sizeof job->sandbox_root, "%s/sandbox/%s-%s",
             data_dir, job->patch->package_name, job->installed);
    job->target.source_root = job->source_root;
    job->target.sandbox_root = job->sandbox_root;

    if (!diag_is_dir(job->source_root)) {
        fprintf(stderr, "legacyguard: no source tree for %s %s (%s)\n",
                job->patch->package_name, job->installed, job->source_root);
        patchdb_free(&job->db);
        return EXIT_FAILURE;
    }

    char diff_path[LG_PATH_MAX * 2];
    int line = 0;
    snprintf(diff_path, sizeof diff_path, "%s/patches/%s",
             data_dir, job->patch->patch_file);
    lg_status st = diff_parse_file(diff_path, &job->diff, &line);
    if (st != LG_OK) {
        patchdb_free(&job->db);
        return fail(diff_path, st, line);
    }

    printf("Patch:   %s  (%s)\n", job->patch->patch_id, job->patch->cve_id);
    printf("Written: %s %s\n", job->patch->package_name,
           job->patch->upstream_version);
    printf("Target:  %s %s  [%s]\n\n", job->patch->package_name,
           job->installed, job->source_root);
    log_msg(LOG_INFO, "Patch %s loaded for %s %s", job->patch->patch_id,
            job->patch->package_name, job->installed);
    return 0;
}

static int cmd_patch_list(void)
{
    PatchDB db;
    if (load_patches(&db))
        return EXIT_FAILURE;
    printf("%-14s %-16s %-10s %-12s %s\n",
           "PATCH", "CVE", "PACKAGE", "WRITTEN FOR", "STATUS");
    for (size_t i = 0; i < db.count; i++) {
        const SecurityPatch *p = &db.items[i];
        printf("%-14s %-16s %-10s %-12s %s\n", p->patch_id, p->cve_id,
               p->package_name, p->upstream_version,
               p->applied ? "applied (sandbox)" : "not applied");
    }
    patchdb_free(&db);
    return 0;
}

static int cmd_patch_check(const char *id)
{
    PatchJob job;
    if (job_open(&job, id))
        return EXIT_FAILURE;

    log_msg(LOG_INFO, "Patch compatibility check started for %s", id);
    PatchCheckSummary s;
    PatchVerdict v = patch_check(&job.diff, &job.target, stdout, &s);
    printf("\nResult: %s  (%zu hunk(s): %zu ok, %zu offset, %zu fuzz, "
           "%zu already applied, %zu failed)\n",
           patch_verdict_name(v), s.hunks, s.clean, s.offset, s.fuzz,
           s.already, s.failed);

    job_free(&job);
    return v == VERDICT_CONFLICT ? EXIT_FINDINGS : 0;
}

static int cmd_patch_apply(const char *id, int reverse)
{
    PatchJob job;
    if (job_open(&job, id))
        return EXIT_FAILURE;

    int rc = 0;
    if (!reverse && job.patch->applied) {
        fprintf(stderr, "legacyguard: %s is already applied\n", id);
        rc = EXIT_FAILURE;
    } else if (reverse && !job.patch->applied) {
        fprintf(stderr, "legacyguard: %s is not applied\n", id);
        rc = EXIT_FAILURE;
    } else {
        lg_status st = patch_apply(&job.diff, &job.target, reverse, stdout);
        if (st == LG_OK) {
            job.patch->applied = !reverse;
            char path[LG_PATH_MAX];
            data_path(path, sizeof path, "patches.txt");
            st = patchdb_save(&job.db, path);
        }
        if (st == LG_OK) {
            printf("\n%s %s in sandbox\n", reverse ? "Reverted" : "Applied", id);
            log_msg(LOG_INFO, "Patch %s %s", id,
                    reverse ? "reverted" : "simulation completed");
        } else {
            log_msg(LOG_ERROR, "Patch %s %s failed: %s", id,
                    reverse ? "revert" : "apply", lg_strerror(st));
            fprintf(stderr, "\nlegacyguard: %s failed, sandbox left "
                            "unchanged: %s\n", id, lg_strerror(st));
            rc = st == LG_ERR_CONFLICT ? EXIT_FINDINGS : EXIT_FAILURE;
        }
    }
    job_free(&job);
    return rc;
}

static int cmd_backport(const char *id)
{
    PatchJob job;
    if (job_open(&job, id))
        return EXIT_FAILURE;

    char api_map[LG_PATH_MAX];
    data_path(api_map, sizeof api_map, "api_map.txt");

    BackportReport rep;
    backport_analyze(&job.diff, &job.target, api_map, stdout, &rep);
    job_free(&job);
    return rep.verdict == BACKPORT_MANUAL ? EXIT_FINDINGS : 0;
}

/* -------------------------------------------------------------- main */

int main(int argc, char **argv)
{
    int opt, verbose = 0;

    /* keep stdout and stderr in order when both go to a pipe */
    setvbuf(stdout, NULL, _IOLBF, 0);
    while ((opt = getopt(argc, argv, "+d:vh")) != -1) {
        switch (opt) {
        case 'd': data_dir = optarg; break;
        case 'v': verbose = 1; break;
        case 'h': usage(stdout); return 0;
        default:  usage(stderr); return EXIT_FAILURE;
        }
    }
    argc -= optind;
    argv += optind;
    if (argc < 1) {
        usage(stderr);
        return EXIT_FAILURE;
    }

    char log_path[LG_PATH_MAX];
    data_path(log_path, sizeof log_path, "legacyguard.log");
    logger_init(log_path);
    logger_set_verbose(verbose);

    const char *cmd = argv[0];
    int rc;

    if (strcmp(cmd, "list") == 0 || strcmp(cmd, "add") == 0 ||
        strcmp(cmd, "remove") == 0 || strcmp(cmd, "update") == 0) {
        rc = cmd_packages(argc, argv);
    } else if (strcmp(cmd, "scan") == 0 && argc == 1) {
        rc = cmd_scan();
    } else if (strcmp(cmd, "compare") == 0 && argc == 3) {
        rc = cmd_compare(argv[1], argv[2]);
    } else if (strcmp(cmd, "patch") == 0 && argc == 2 &&
               strcmp(argv[1], "list") == 0) {
        rc = cmd_patch_list();
    } else if (strcmp(cmd, "patch") == 0 && argc == 3) {
        if (strcmp(argv[1], "check") == 0)
            rc = cmd_patch_check(argv[2]);
        else if (strcmp(argv[1], "apply") == 0)
            rc = cmd_patch_apply(argv[2], 0);
        else if (strcmp(argv[1], "revert") == 0)
            rc = cmd_patch_apply(argv[2], 1);
        else {
            usage(stderr);
            rc = EXIT_FAILURE;
        }
    } else if (strcmp(cmd, "backport") == 0 && argc == 2) {
        rc = cmd_backport(argv[1]);
    } else if (strcmp(cmd, "diag") == 0 && argc == 1) {
        rc = diag_report(data_dir);
    } else {
        usage(stderr);
        rc = EXIT_FAILURE;
    }

    logger_close();
    return rc;
}
