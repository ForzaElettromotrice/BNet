#include "logger.h"

void E_Print(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    fprintf(stderr, RED "Error: " RESET);
    vfprintf(stderr, msg, args);
    va_end(args);
}
