#include "csprng.h"

#ifdef _WIN32
#include <bcrypt.h>
#include <windows.h>
#pragma comment(lib, "Bcrypt.lib")
#else
#include <cstdio>
#endif

namespace file_encrypt::algorithm {

int GetRandom(char* buf, int bufsiz) {
#ifdef _WIN32
  if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, reinterpret_cast<UCHAR*>(buf),
                                      bufsiz, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
    return -1;
  return 0;
#else
  static std::FILE* urandom = fopen("/dev/urandom", "rb");
  if (!urandom) return -1;
  size_t n = std::fread(buf, 1, bufsiz, urandom);
  if (n != (size_t)bufsiz) return -1;
  return 0;
#endif
}

}  // namespace file_encrypt::algorithm