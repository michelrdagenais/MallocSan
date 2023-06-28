#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "dw-log.h"

char* dw_log_level_name[] = {"ERROR", "WARNING", "INFO", "DEBUG"};

struct dw_log_category {
    char *name;
    int active;
    int level;
};

struct dw_log_category dw_log_categories[] = {{"protect", 1, 2}, {"disassembly", 1, 2}, {"main", 1, 2}, {"wrap", 1, 2}};

// We call directly write to avoid the wrappers.
ssize_t __write(int fd, const void *buf, size_t count);

void dw_log(enum dw_log_level level, enum dw_log_category_name topic, const char *fmt, ...) 
{
    char buffer[1024];
    
    // This message is not within the log level, return without printing it
    if(dw_log_categories[topic].active == 0 || level > dw_log_categories[topic].level) return; 

    // Write to a stack buffer and then call the low level write. We avoid any malloc that glibc could do
    // First the level name and category name
    int ret = snprintf(buffer, 1024, "%s %s: ", dw_log_level_name[level], dw_log_categories[topic].name);
    __write(2, buffer, ret);
    
    // Then write the user supplied format and arguments
    va_list args;
    va_start(args, fmt);
    ret = vsnprintf(buffer, 1024, fmt, args);
    __write(2, buffer, ret);
    va_end(args);
    
    // If the log level is "ERROR", this is fatal and the program exits
    if(level == ERROR) exit(1);
}

// Simple fprintf facility that should not use malloc
void dw_fprintf(int fd, const char *fmt, ...) 
{
    char buffer[1024];

    va_list args;
    va_start(args, fmt);
    int ret = vsnprintf(buffer, 1024, fmt, args);
    __write(fd, buffer, ret);
    va_end(args);
}

// Set a new log level, the same for all categories
// We could eventually allow setting a different level for each category
void dw_set_log_level(enum dw_log_level level)
{
    if(level < 0) return;
    for(int i = 0; i < WRAP; i++) dw_log_categories[i].level = level;
}
