#include "minitest.h"
#include "cve_scanner.h"
#include "package_manager.h"

static Vulnerability vuln(const char *pkg, const char *from, const char *fixed)
{
    Vulnerability v;
    memset(&v, 0, sizeof v);
    strcpy(v.cve_id, "CVE-TEST-1");
    strcpy(v.package_name, pkg);
    strcpy(v.affected_version, from);
    strcpy(v.fixed_version, fixed);
    v.severity = SEV_HIGH;
    return v;
}

TEST(affected_range_is_half_open)
{
    Vulnerability v = vuln("openssl", "1.0.2", "1.1.1w");
    CHECK(!vuln_affects(&v, "openssl", "1.0.1"));  /* before introduction */
    CHECK(vuln_affects(&v, "openssl", "1.0.2"));   /* first affected */
    CHECK(vuln_affects(&v, "openssl", "1.1.1k"));
    CHECK(!vuln_affects(&v, "openssl", "1.1.1w")); /* fixed release */
    CHECK(!vuln_affects(&v, "openssl", "3.0.0"));
    CHECK(!vuln_affects(&v, "curl", "1.1.1k"));    /* other package */
}

TEST(wildcard_means_all_older_versions)
{
    Vulnerability v = vuln("curl", "*", "7.20.0");
    CHECK(vuln_affects(&v, "curl", "0.1"));
    CHECK(vuln_affects(&v, "curl", "7.19.9"));
    CHECK(!vuln_affects(&v, "curl", "7.20.0"));
}

TEST(severity_parsing)
{
    CHECK_EQ_INT(severity_parse("CRITICAL"), SEV_CRITICAL);
    CHECK_EQ_INT(severity_parse("low"), SEV_LOW);
    CHECK_EQ_INT(severity_parse("urgent"), -1);
}

TEST(package_list_operations)
{
    PackageList l;
    pkglist_init(&l);
    CHECK_EQ_INT(pkglist_add(&l, "openssl", "1.1.1k", "CentOS 7"), LG_OK);
    CHECK_EQ_INT(pkglist_add(&l, "openssl", "1.1.1", "x"), LG_ERR_EXISTS);
    CHECK_EQ_INT(pkglist_add(&l, "php", "7..2", "x"), LG_ERR_VERSION);
    CHECK_EQ_INT(pkglist_add(&l, "a|b", "1.0", "x"), LG_ERR_FORMAT);
    CHECK_EQ_INT(pkglist_set_version(&l, "openssl", "1.1.1w"), LG_OK);
    CHECK_EQ_STR(pkglist_find(&l, "openssl")->version, "1.1.1w");
    CHECK_EQ_INT(pkglist_remove(&l, "nope"), LG_ERR_NOT_FOUND);

    /* growth beyond the initial capacity */
    for (int i = 0; i < 50; i++) {
        char name[16];
        snprintf(name, sizeof name, "pkg%d", i);
        CHECK_EQ_INT(pkglist_add(&l, name, "1.0", "test"), LG_OK);
    }
    CHECK_EQ_INT(l.count, 51);
    CHECK_EQ_INT(pkglist_remove(&l, "pkg0"), LG_OK);
    CHECK(pkglist_find(&l, "pkg0") == NULL);
    CHECK(pkglist_find(&l, "pkg49") != NULL);
    pkglist_free(&l);
}

TEST(package_list_save_load_roundtrip)
{
    const char *dir = mt_tempdir();
    char path[128];
    snprintf(path, sizeof path, "%s/packages.txt", dir);

    PackageList a, b;
    pkglist_init(&a);
    pkglist_init(&b);
    pkglist_add(&a, "nginx", "1.18.0", "Debian 11");
    pkglist_add(&a, "curl", "7.29.0", "CentOS 7");
    CHECK_EQ_INT(pkglist_save(&a, path), LG_OK);
    CHECK_EQ_INT(pkglist_load(&b, path, NULL), LG_OK);
    CHECK_EQ_INT(b.count, 2);
    CHECK_EQ_STR(b.items[0].distribution, "Debian 11");
    CHECK_EQ_STR(b.items[1].version, "7.29.0");
    pkglist_free(&a);
    pkglist_free(&b);

    /* a malformed line is reported with its number */
    mt_write_file(path, "# header\nnginx | 1.18.0 | Debian\ncurl | 7.29\n");
    int bad = 0;
    pkglist_init(&b);
    CHECK_EQ_INT(pkglist_load(&b, path, &bad), LG_ERR_FORMAT);
    CHECK_EQ_INT(bad, 3);
    pkglist_free(&b);
    mt_rmtree(dir);
}

TEST(scan_counts_findings)
{
    const char *dir = mt_tempdir();
    char path[128];
    snprintf(path, sizeof path, "%s/vulns.txt", dir);
    mt_write_file(path,
        "# comment\n"
        "CVE-A | openssl | 1.0.2 | 1.1.1w | CRITICAL | a\n"
        "CVE-B | openssl | 3.0.0 | 3.0.13 | HIGH | b\n"
        "CVE-C | php | * | 7.2.34 | HIGH | c\n"
        "CVE-D | php | 7.0.0 | 7.4.0 | LOW | d\n");

    VulnDB db;
    vulndb_init(&db);
    CHECK_EQ_INT(vulndb_load(&db, path, NULL), LG_OK);
    CHECK_EQ_INT(db.count, 4);

    PackageList l;
    pkglist_init(&l);
    pkglist_add(&l, "openssl", "1.1.1k", "x");
    pkglist_add(&l, "php", "7.2.0", "x");
    pkglist_add(&l, "curl", "7.29.0", "x");

    ScanSummary s;
    scan_packages(&l, &db, NULL, &s);
    CHECK_EQ_INT(s.total_packages, 3);
    CHECK_EQ_INT(s.vulnerable_packages, 2);
    CHECK_EQ_INT(s.findings, 3);
    CHECK_EQ_INT(s.by_severity[SEV_CRITICAL], 1);
    CHECK_EQ_INT(s.by_severity[SEV_HIGH], 1);
    CHECK_EQ_INT(s.by_severity[SEV_LOW], 1);

    pkglist_free(&l);
    vulndb_free(&db);

    /* invalid severity is rejected */
    mt_write_file(path, "CVE-X | php | * | 7.2.34 | BAD | x\n");
    vulndb_init(&db);
    CHECK_EQ_INT(vulndb_load(&db, path, NULL), LG_ERR_FORMAT);
    vulndb_free(&db);
    mt_rmtree(dir);
}

int main(void)
{
    printf("test_scanner\n");
    RUN(affected_range_is_half_open);
    RUN(wildcard_means_all_older_versions);
    RUN(severity_parsing);
    RUN(package_list_operations);
    RUN(package_list_save_load_roundtrip);
    RUN(scan_counts_findings);
    return TEST_REPORT("test_scanner");
}
