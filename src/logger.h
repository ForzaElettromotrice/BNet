#pragma once

#include <stdio.h>
#include <stdarg.h>

#define RED       "\033[31m"
#define GREEN     "\033[32m"
#define YELLOW    "\033[33m"
#define BLUE      "\033[34m"
#define BOLD      "\033[1m"
#define ITALIC    "\033[3m"
#define UNDERLINE "\033[4m"
#define RESET     "\033[0m"


void E_Print(const char *msg, ...);
void D_Print(const char *msg, ...);