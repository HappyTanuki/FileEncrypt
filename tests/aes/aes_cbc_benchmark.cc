#include <ctime>
#include <iostream>
#include <span>

#include "algorithm/block_cipher/mode/aliases.h"
#include "algorithm/csprng/csprng.h"

#define _KEY_BIT 256
#define _ALGORITHM file_encrypt::algorithm::AES_CBC<_KEY_BIT>
#define _ITERATIONS 10000000
#define _PROCESSED_BYTES (16 * _ITERATIONS)

int main() {
  std::array<std::byte, 16> buffer = {};
  file_encrypt::algorithm::CSPRNG::GetRandom(
      reinterpret_cast<char*>(buffer.data()), 16);

  double _PROCESSED_KILOBYTES = double(_PROCESSED_BYTES) / 1024.0;

  _ALGORITHM cipher;

  auto start_time = std::clock();

  for (std::uint64_t i = 0; i < _ITERATIONS; i++) {
    cipher << buffer;
  }

  auto end_time = std::clock();

  double elapsed_time = double(end_time - start_time) / CLOCKS_PER_SEC;
  std::cout << "Elapsed time: " << elapsed_time << " seconds" << std::endl;
  std::cout << "bytes_processed: " << _PROCESSED_KILOBYTES << "kb" << std::endl;
  std::cout << "throughput: " << _PROCESSED_KILOBYTES / elapsed_time << "kb/s"
            << std::endl;

  return 0;
}