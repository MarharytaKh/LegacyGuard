#include "cve_scanner.h"
#include "logger.h"
#include "version.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define REPORT_RULE  "========================================"
#define REPORT_SEP   "----------------------------------------"

void vulndb_init(VulnDB *db)
{
    db->items = NULL;
    db->count = 0;
    db->capacity = 0;
}

void vulndb_free(VulnDB *db)
{
    free(db->items);
    vulndb_init(db);
}

const char *severity_name(Severity s)
{
    switch (s) {
    case SEV_LOW:      return "LOW";
    case SEV_MEDIUM:   return "MEDIUM";
    case SEV_HIGH:     return "HIGH";
    case SEV_CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

int severity_parse(const char *s)
{
    static const Severity all[] = { SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL };
    for (size_t i = 0; i < sizeof all / sizeof all[0]; i++)
        if (strcasecmp(s, severity_name(all[i])) == 0)
            return (int)all[i];
    return -1;
}

static lg_status vulndb_push(VulnDB *db, const Vulnerability *v)
{
    if (db->count == db->capacity) {
        size_t cap = db->capacity ? db->capacity * 2 : 16;
        Vulnerability *items = realloc(db->items, cap * sizeof *items);
        if (!items)
            return LG_ERR_NOMEM;
        db->items = items;
        db->capacity = cap;
    }
    db->items[db->count++] = *v;
    return LG_OK;
}

lg_status vulndb_load(VulnDB *db, const char *path, int *bad_line)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        log_msg(LOG_ERROR, "Cannot open vulnerability DB %s", path);
        return LG_ERR_IO;
    }

    char line[LG_LINE_MAX];
    int lineno = 0;
    lg_status st = LG_OK;

    while (fgets(line, sizeof line, f)) {
        lineno++;
        if (lg_is_blank_or_comment(line))
            continue;

        char *fld[6];
        Vulnerability v;
        int sev;

        if (lg_split(line, '|', fld, 6) != 6 ||
            (sev = severity_parse(fld[4])) < 0) {
            st = LG_ERR_FORMAT;
        } else if ((strcmp(fld[2], "*") != 0 && !version_is_valid(fld[2])) ||
                   !version_is_valid(fld[3])) {
            st = LG_ERR_VERSION;
        } else {
            lg_strlcpy(v.cve_id, fld[0], sizeof v.cve_id);
            lg_strlcpy(v.package_name, fld[1], sizeof v.package_name);
            lg_strlcpy(v.affected_version, fld[2], sizeof v.affected_version);
            lg_strlcpy(v.fixed_version, fld[3], sizeof v.fixed_version);
            v.severity = (Severity)sev;
            lg_strlcpy(v.description, fld[5], sizeof v.description);
            st = vulndb_push(db, &v);
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

int vuln_affects(const Vulnerability *v, const char *package,
                 const char *version)
{
    if (strcmp(v->package_name, package) != 0)
        return 0;
    if (strcmp(v->affected_version, "*") != 0 &&
        version_compare(version, v->affected_version) < 0)
        return 0; /* older than the version that introduced the bug */
    return version_compare(version, v->fixed_version) < 0;
}

void scan_packages(const PackageList *pkgs, const VulnDB *db,
                   FILE *out, ScanSummary *summary)
{
    memset(summary, 0, sizeof *summary);
    summary->total_packages = pkgs->count;

    if (out)
        fprintf(out, "%s\n          SECURITY SCAN REPORT\n%s\n",
                REPORT_RULE, REPORT_RULE);

    for (size_t i = 0; i < pkgs->count; i++) {
        const Package *p = &pkgs->items[i];
        size_t hits = 0;

        if (out)
            fprintf(out, "\nPackage: %s\nVersion: %s (%s)\n",
                    p->name, p->version, p->distribution);

        for (size_t j = 0; j < db->count; j++) {
            const Vulnerability *v = &db->items[j];
            if (!vuln_affects(v, p->name, p->version))
                continue;

            hits++;
            summary->findings++;
            summary->by_severity[v->severity]++;
            log_msg(LOG_WARN, "%s detected in %s %s",
                    v->cve_id, p->name, p->version);

            if (out)
                fprintf(out, "\n  CVE:      %s\n  Severity: %s\n"
                             "  Affected: %s <= v < %s\n  Summary:  %s\n",
                        v->cve_id, severity_name(v->severity),
                        v->affected_version, v->fixed_version,
                        v->description);
        }

        if (hits) {
            summary->vulnerable_packages++;
            if (out)
                fprintf(out, "\nStatus: VULNERABLE (%zu CVE%s)\n"
                             "Recommended action: apply security patch "
                             "(see `legacyguard patch list`)\n",
                        hits, hits == 1 ? "" : "s");
        } else if (out) {
            fprintf(out, "\nStatus: NO KNOWN VULNERABILITIES\n");
        }
        if (out)
            fprintf(out, "\n%s\n", REPORT_SEP);
    }

    if (out) {
        fprintf(out, "Total packages:      %zu\n", summary->total_packages);
        fprintf(out, "Vulnerable packages: %zu\n", summary->vulnerable_packages);
        fprintf(out, "Findings:            %zu  (critical %zu, high %zu, "
                     "medium %zu, low %zu)\n",
                summary->findings,
                summary->by_severity[SEV_CRITICAL],
                summary->by_severity[SEV_HIGH],
                summary->by_severity[SEV_MEDIUM],
                summary->by_severity[SEV_LOW]);
        fprintf(out, "%s\n", REPORT_RULE);
    }
    log_msg(LOG_INFO, "Scan finished: %zu/%zu packages vulnerable",
            summary->vulnerable_packages, summary->total_packages);
}
