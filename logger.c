#include "logger.h"

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static FILE *log_file = NULL;
static int log_verbose = 0;

static const char *level_name(log_level level)
{
    switch (level) {
    case LOG_DEBUG: return "DEBUG";
    case LOG_INFO:  return "INFO";
    case LOG_WARN:  return "WARN";
    case LOG_ERROR: return "ERROR";
    }
    return "?";
}

int logger_init(const char *path)
{
    logger_close();
    log_file = fopen(path, "a");
    return log_file ? 0 : -1;
}

void logger_set_verbose(int verbose)
{
    log_verbose = verbose;
}

void log_msg(log_level level, const char *fmt, ...)
{
    if (!log_file && !log_verbose)
        return;

    char stamp[32];
    time_t now = time(NULL);
    struct tm tm_now;
    localtime_r(&now, &tm_now);
    strftime(stamp, sizeof stamp, "%Y-%m-%d %H:%M:%S", &tm_now);

    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);

    if (log_file) {
        fprintf(log_file, "[%s] [%s] %s\n", stamp, level_name(level), msg);
        fflush(log_file);
    }
    if (log_verbose)
        fprintf(stderr, "[%s] [%s] %s\n", stamp, level_name(level), msg);
}

void logger_close(void)
{
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}
