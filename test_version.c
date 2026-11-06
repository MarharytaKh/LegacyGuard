#include "minitest.h"
#include "version.h"

static int sign(int x) { return (x > 0) - (x < 0); }

TEST(numeric_components_are_compared_as_numbers)
{
    CHECK_EQ_INT(sign(version_compare("1.2.9", "1.2.10")), -1);
    CHECK_EQ_INT(sign(version_compare("2.0.0", "1.9.9")), 1);
    CHECK_EQ_INT(sign(version_compare("7.2.15", "7.2.16")), -1);
    CHECK_EQ_INT(sign(version_compare("10.0", "9.99")), 1);
    /* string comparison would get these wrong */
    CHECK(strcmp("1.2.9", "1.2.10") > 0);
}

TEST(equal_versions)
{
    CHECK_EQ_INT(version_compare("1.1.1", "1.1.1"), 0);
    CHECK_EQ_INT(version_compare("1.01", "1.1"), 0);  /* leading zeros */
    CHECK_EQ_INT(version_compare("1.0-1", "1.0.1"), 0); /* separators equal */
}

TEST(letter_suffixes)
{
    CHECK_EQ_INT(sign(version_compare("1.1.1k", "1.1.1w")), -1);
    CHECK_EQ_INT(sign(version_compare("1.1.1", "1.1.1k")), -1);
    CHECK_EQ_INT(sign(version_compare("1.1.1z", "1.1.2")), -1);
    /* numeric run beats an alphabetic one */
    CHECK_EQ_INT(sign(version_compare("1.0.1", "1.0.a")), 1);
}

TEST(longer_version_is_newer)
{
    CHECK_EQ_INT(sign(version_compare("1.2", "1.2.1")), -1);
    CHECK_EQ_INT(sign(version_compare("1.2.0.1", "1.2")), 1);
}

TEST(tilde_marks_prerelease)
{
    CHECK_EQ_INT(sign(version_compare("8.0.0~rc1", "8.0.0")), -1);
    CHECK_EQ_INT(sign(version_compare("8.0.0~rc1", "8.0.0~rc2")), -1);
    CHECK_EQ_INT(sign(version_compare("8.0.0~rc1", "7.4.33")), 1);
}

TEST(huge_numbers_do_not_overflow)
{
    CHECK_EQ_INT(sign(version_compare("1.99999999999999999999",
                                      "1.100000000000000000000")), -1);
}

TEST(compare_is_antisymmetric)
{
    const char *v[] = { "0.9", "1.0~beta", "1.0", "1.0a", "1.0.1", "1.2.10",
                        "1.10", "2.0", "2.0.0.1" };
    size_t n = sizeof v / sizeof v[0];
    for (size_t i = 0; i < n; i++)
        for (size_t j = 0; j < n; j++) {
            CHECK_EQ_INT(sign(version_compare(v[i], v[j])),
                         -sign(version_compare(v[j], v[i])));
            /* the list is sorted, so the order must agree with indices */
            CHECK_EQ_INT(sign(version_compare(v[i], v[j])),
                         (i > j) - (i < j));
        }
}

TEST(validity)
{
    CHECK(version_is_valid("1.1.1"));
    CHECK(version_is_valid("1.1.1k"));
    CHECK(version_is_valid("7.29.0-el7"));
    CHECK(version_is_valid("8.0.0~rc1"));
    CHECK(!version_is_valid(""));
    CHECK(!version_is_valid("v1.0"));
    CHECK(!version_is_valid("1..2"));
    CHECK(!version_is_valid("1.2."));
    CHECK(!version_is_valid("1.2 3"));
    CHECK(!version_is_valid("1.2|3"));
    CHECK(!version_is_valid(NULL));
}

int main(void)
{
    printf("test_version\n");
    RUN(numeric_components_are_compared_as_numbers);
    RUN(equal_versions);
    RUN(letter_suffixes);
    RUN(longer_version_is_newer);
    RUN(tilde_marks_prerelease);
    RUN(huge_numbers_do_not_overflow);
    RUN(compare_is_antisymmetric);
    RUN(validity);
    return TEST_REPORT("test_version");
}
