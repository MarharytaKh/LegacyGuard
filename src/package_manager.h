/*
 * package_manager.h - list of installed packages.
 *
 * File format (data/packages.txt), one package per line:
 *     name | version | distribution
 * Lines starting with '#' are comments.
 */
#ifndef LG_PACKAGE_MANAGER_H
#define LG_PACKAGE_MANAGER_H

#include <stddef.h>
#include "common.h"

typedef struct {
    char name[LG_NAME_MAX];
    char version[LG_VERSION_MAX];
    char distribution[LG_NAME_MAX];
} Package;

typedef struct {
    Package *items;
    size_t count;
    size_t capacity;
} PackageList;

void pkglist_init(PackageList *list);
void pkglist_free(PackageList *list);

/* On a malformed line, *bad_line (if not NULL) receives its line number. */
lg_status pkglist_load(PackageList *list, const char *path, int *bad_line);
lg_status pkglist_save(const PackageList *list, const char *path);

lg_status pkglist_add(PackageList *list, const char *name,
                      const char *version, const char *distribution);
lg_status pkglist_remove(PackageList *list, const char *name);
lg_status pkglist_set_version(PackageList *list, const char *name,
                              const char *version);

Package *pkglist_find(const PackageList *list, const char *name);

void pkglist_print(const PackageList *list);

#endif /* LG_PACKAGE_MANAGER_H */
