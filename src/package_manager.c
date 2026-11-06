#include "package_manager.h"
#include "logger.h"
#include "version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void pkglist_init(PackageList *list)
{
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

void pkglist_free(PackageList *list)
{
    free(list->items);
    pkglist_init(list);
}

static lg_status pkglist_reserve(PackageList *list, size_t needed)
{
    if (needed <= list->capacity)
        return LG_OK;

    size_t cap = list->capacity ? list->capacity * 2 : 8;
    while (cap < needed)
        cap *= 2;

    Package *items = realloc(list->items, cap * sizeof *items);
    if (!items)
        return LG_ERR_NOMEM;
    list->items = items;
    list->capacity = cap;
    return LG_OK;
}

Package *pkglist_find(const PackageList *list, const char *name)
{
    for (size_t i = 0; i < list->count; i++)
        if (strcmp(list->items[i].name, name) == 0)
            return &list->items[i];
    return NULL;
}

lg_status pkglist_add(PackageList *list, const char *name,
                      const char *version, const char *distribution)
{
    if (name[0] == '\0' || strlen(name) >= LG_NAME_MAX ||
        strchr(name, '|') || strlen(distribution) >= LG_NAME_MAX ||
        strchr(distribution, '|'))
        return LG_ERR_FORMAT;
    if (!version_is_valid(version))
        return LG_ERR_VERSION;
    if (pkglist_find(list, name))
        return LG_ERR_EXISTS;

    lg_status st = pkglist_reserve(list, list->count + 1);
    if (st != LG_OK)
        return st;

    Package *p = &list->items[list->count++];
    lg_strlcpy(p->name, name, sizeof p->name);
    lg_strlcpy(p->version, version, sizeof p->version);
    lg_strlcpy(p->distribution, distribution, sizeof p->distribution);
    return LG_OK;
}

lg_status pkglist_remove(PackageList *list, const char *name)
{
    Package *p = pkglist_find(list, name);
    if (!p)
        return LG_ERR_NOT_FOUND;

    size_t idx = (size_t)(p - list->items);
    memmove(&list->items[idx], &list->items[idx + 1],
            (list->count - idx - 1) * sizeof *p);
    list->count--;
    return LG_OK;
}

lg_status pkglist_set_version(PackageList *list, const char *name,
                              const char *version)
{
    if (!version_is_valid(version))
        return LG_ERR_VERSION;
    Package *p = pkglist_find(list, name);
    if (!p)
        return LG_ERR_NOT_FOUND;
    lg_strlcpy(p->version, version, sizeof p->version);
    return LG_OK;
}

lg_status pkglist_load(PackageList *list, const char *path, int *bad_line)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        log_msg(LOG_ERROR, "Cannot open package list %s", path);
        return LG_ERR_IO;
    }

    char line[LG_LINE_MAX];
    int lineno = 0;
    lg_status st = LG_OK;

    while (fgets(line, sizeof line, f)) {
        lineno++;
        if (lg_is_blank_or_comment(line))
            continue;

        char *fields[3];
        if (lg_split(line, '|', fields, 3) != 3) {
            st = LG_ERR_FORMAT;
        } else {
            st = pkglist_add(list, fields[0], fields[1], fields[2]);
        }
        if (st != LG_OK) {
            if (bad_line)
                *bad_line = lineno;
            log_msg(LOG_ERROR, "%s:%d: %s", path, lineno, lg_strerror(st));
            break;
        }
        log_msg(LOG_DEBUG, "Package %s %s detected", fields[0], fields[1]);
    }

    fclose(f);
    return st;
}

lg_status pkglist_save(const PackageList *list, const char *path)
{
    /* Write to a temporary file first so a failed write never
     * leaves a half-written package list behind. */
    char tmp[LG_PATH_MAX + 8];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);

    FILE *f = fopen(tmp, "w");
    if (!f)
        return LG_ERR_IO;

    fprintf(f, "# name | version | distribution\n");
    for (size_t i = 0; i < list->count; i++) {
        const Package *p = &list->items[i];
        fprintf(f, "%s | %s | %s\n", p->name, p->version, p->distribution);
    }

    if (fclose(f) != 0 || rename(tmp, path) != 0) {
        remove(tmp);
        return LG_ERR_IO;
    }
    return LG_OK;
}

void pkglist_print(const PackageList *list)
{
    printf("%-16s %-14s %s\n", "PACKAGE", "VERSION", "DISTRIBUTION");
    printf("%-16s %-14s %s\n", "-------", "-------", "------------");
    for (size_t i = 0; i < list->count; i++) {
        const Package *p = &list->items[i];
        printf("%-16s %-14s %s\n", p->name, p->version, p->distribution);
    }
    printf("\n%zu package(s)\n", list->count);
}
