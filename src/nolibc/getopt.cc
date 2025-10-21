#include "nolibc/getopt.h"

namespace nolibc {
char* optarg;
int optind = 1, opterr = 1, optopt;

int getopt(int argc, char* const argv[], const char* optstring) {
  static int __optpos;
  int i;
  char c, d;
  char* optchar;

  if (!optind) {
    __optpos = 0;
    optind = 1;
  }

  if (optind >= argc || !argv[optind]) return -1;

  if (argv[optind][0] != '-') {
    if (optstring[0] == '-') {
      optarg = argv[optind++];
      return 1;
    }
    return -1;
  }

  if (!argv[optind][1]) return -1;

  if (argv[optind][1] == '-' && !argv[optind][2]) return optind++, -1;

  if (!__optpos) __optpos++;
  c = argv[optind][__optpos];
  optchar = argv[optind] + __optpos;
  __optpos++;

  if (!argv[optind][__optpos]) {
    optind++;
    __optpos = 0;
  }

  if (optstring[0] == '-' || optstring[0] == '+') optstring++;

  i = 0;
  d = 0;
  do {
    d = optstring[i++];
  } while (d && d != c);

  if (d != c || c == ':') {
    optopt = c;
    if (optstring[0] != ':' && opterr)
      std::fprintf(stderr, "%s: unrecognized option: %c\n", argv[0], *optchar);
    return '?';
  }
  if (optstring[i] == ':') {
    optarg = 0;
    if (optstring[i + 1] != ':' || __optpos) {
      optarg = argv[optind++];
      if (__optpos) optarg += __optpos;
      __optpos = 0;
    }
    if (optind > argc) {
      optopt = c;
      if (optstring[0] == ':') return ':';
      if (opterr)
        std::fprintf(stderr, "%s: option requires argument: %c\n", argv[0],
                     *optchar);
      return '?';
    }
  }
  return c;
}
}