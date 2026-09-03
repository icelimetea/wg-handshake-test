#ifndef LOG_H
#define LOG_H

#include <stdio.h>

#define LOG_ERROR(template, ...) fprintf(stderr, "ERROR: " template "\n" __VA_OPT__(,) __VA_ARGS__)
#define LOG_INFO(template, ...) fprintf(stdout, template "\n" __VA_OPT__(,) __VA_ARGS__)

#endif
