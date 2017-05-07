// ---------------------------------------------------------------------------------------
//  File: utils.h
// Author: Carter Shean  Login: cshea892  Class: CpS 320
//  Desc:   This file contains the #include statements and prototpye
//             for the blog method to be used in the webserver.c file
// --------------------------------------------------------------------------------------

#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>    // For access to C99 "bool" type
#include <stdio.h>      // Standard I/O functions
#include <stdlib.h>     // Other standard library functions
#include <string.h>     // Standard string functions
#include <errno.h>      // Global errno variable
#include <sys/stat.h>

#include <stdarg.h>     // Variadic argument lists (for blog function)
#include <time.h>       // Time/date formatting function (for blog function)

#include <pthread.h>
#include <unistd.h>     // Standard system calls
#include <signal.h>     // Signal handling system calls (sigaction(2))


// Generic log-to-stdout logging routine
void blog(const char *fmt, ...);

#endif