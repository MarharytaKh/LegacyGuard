/*
 * cve_scanner.h - match installed packages against a vulnerability database.
 *
 * File format (data/vulnerabilities.txt):
 *     cve_id | package | introduced_in | fixed_in | severity | description
 *
 * A package version V is affected when  introduced_in <= V < fixed_in.
 * Use '*' for introduced_in when every version before fixed_in is affected.
 */
#ifndef LG_CVE_SCANNER_H
#define LG_CVE_SCANNER_H

#include <stdio.h>
#include "common.h"
#include "package_manager.h"

typedef enum {
    SEV_LOW = 1,
    SEV_MEDIUM = 2,
    SEV_HIGH = 3,
    SEV_CRITICAL = 4
} Severity;

typedef struct {
    char cve_id[LG_ID_MAX];
    char package_name[LG_NAME_MAX];
    char affected_version[LG_VERSION_MAX]; /* first affected version or "*" */
    char fixed_version[LG_VERSION_MAX];
    Severity severity;
    char description[LG_DESC_MAX];
} Vulnerability;

typedef struct {
    Vulnerability *items;
    size_t count;
    size_t capacity;
} VulnDB;

typedef struct {
    size_t total_packages;
    size_t vulnerable_packages;
    size_t findings;           /* total (package, CVE) matches */
    size_t by_severity[5];     /* index = Severity */
} ScanSummary;

void vulndb_init(VulnDB *db);
void vulndb_free(VulnDB *db);
lg_status vulndb_load(VulnDB *db, const char *path, int *bad_line);

const char *severity_name(Severity s);
int severity_parse(const char *s); /* returns Severity or -1 */

/* 1 if this vulnerability affects the given package/version. */
int vuln_affects(const Vulnerability *v, const char *package,
                 const char *version);

/* Prints the report to out (NULL = no output) and fills summary. */
void scan_packages(const PackageList *pkgs, const VulnDB *db,
                   FILE *out, ScanSummary *summary);

#endif /* LG_CVE_SCANNER_H */
