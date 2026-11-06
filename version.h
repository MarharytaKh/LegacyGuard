/*
 * version.h - package version comparison.
 *
 * Versions are split into alternating runs of digits and letters,
 * separators ('.', '-', '_', '+') only delimit runs. Rules (close to rpmvercmp):
 *   - numeric runs are compared as numbers:  1.2.9 < 1.2.10
 *   - alphabetic runs are compared as strings: 1.1.1k < 1.1.1w
 *   - a numeric run is newer than an alphabetic one
 *   - when all common runs are equal, the version with more runs is newer:
 *     1.1.1 < 1.1.1k
 *   - '~' marks a pre-release and sorts before everything: 8.0.0~rc1 < 8.0.0
 */
#ifndef LG_VERSION_H
#define LG_VERSION_H

/* Returns <0 if a < b, 0 if equal, >0 if a > b. */
int version_compare(const char *a, const char *b);

/*
 * Returns 1 if v looks like a package version: starts with a digit,
 * contains only [0-9A-Za-z.-_+~], no empty components ("1..2").
 */
int version_is_valid(const char *v);

#endif /* LG_VERSION_H */
