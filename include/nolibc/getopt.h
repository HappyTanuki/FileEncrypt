/* SPDX-License-Identifier: LGPL-2.1 OR MIT */
/*
 * getopt function definitions for NOLIBC, adapted from musl libc
 * Copyright (C) 2005-2020 Rich Felker, et al.
 * Copyright (C) 2025 Thomas Weißschuh <linux@weissschuh.net>
 */

#ifndef _NOLIBC_GETOPT_H
#define _NOLIBC_GETOPT_H
#include <cstdio>

namespace nolibc {

extern char* optarg;
extern int optind, opterr, optopt;

int getopt(int argc, char* const argv[], const char* optstring);
}  // namespace nolibc

#endif /* _NOLIBC_GETOPT_H */