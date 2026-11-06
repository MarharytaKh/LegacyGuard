/*
 * logger.h - timestamped action log.
 *
 *   [2026-11-06 10:15:22] [INFO] Package openssl detected
 */
#ifndef LG_LOGGER_H
#define LG_LOGGER_H

typedef enum { LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR } log_level;

/* Opens (appends to) the log file. Returns 0 on success, -1 on failure.
 * When the file can't be opened, logging silently goes nowhere. */
int logger_init(const char *path);

/* Also print log lines to stderr (used by -v). */
void logger_set_verbose(int verbose);

void log_msg(log_level level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

void logger_close(void);

#endif /* LG_LOGGER_H */
