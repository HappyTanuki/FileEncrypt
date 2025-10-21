#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_CSPRNG_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_CSPRNG_H_
#include <array>
#include <cstdint>

namespace file_encrypt::algorithm {

int GetRandom(char* buf, int bufsiz);

template <std::uint32_t Size>
std::array<std::byte, Size> GetRandomArray() {
  std::array<std::byte, Size> random = {};
  GetRandom(reinterpret_cast<char*>(random.data()), Size);
  return random;
}
}  // namespace file_encrypt::algorithm

// Implementation details only below here.
#include "csprng.inc"

#endif