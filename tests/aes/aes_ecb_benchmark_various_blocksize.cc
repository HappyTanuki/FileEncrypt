#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <span>
#include <vector>

#include "algorithm/block_cipher/mode/aliases.h"
#include "algorithm/csprng/csprng.h"

#define _KEY_BIT 256
#define _ALGORITHM file_encrypt::algorithm::AES_ECB<_KEY_BIT>
#define _BLOCK_SIZE 16
#define _TEST_SECONDS 10L

template <std::uint32_t BufferSize>
void process_test() {
  std::array<std::byte, BufferSize> buffer = {};
  file_encrypt::algorithm::CSPRNG::GetRandom(
      reinterpret_cast<char*>(buffer.data()), BufferSize);
  std::span<const std::byte, BufferSize> data_span(buffer);

  _ALGORITHM cipher;

  std::uint64_t iterations = 0;
  auto start_time = std::chrono::high_resolution_clock::now();
  auto end_time = start_time;
  const std::uint64_t CHECK_INTERVAL = 1000;

  while (true) {
    for (std::uint64_t i = 0; i < CHECK_INTERVAL; i++) {
      // std::span으로 16B 단위 AES 호출
      for (std::size_t offset = 0; offset < BufferSize; offset += _BLOCK_SIZE) {
        cipher << data_span.subspan(offset, _BLOCK_SIZE);
      }
      iterations++;
    }

    end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<long double> elapsed = end_time - start_time;
    if (elapsed.count() >= _TEST_SECONDS) break;
  }

  std::chrono::duration<long double> elapsed = end_time - start_time;
  long double bytes_processed =
      static_cast<long double>(BufferSize) * iterations;
  long double kb_processed = bytes_processed / 1024.0L;
  long double throughput = kb_processed / elapsed.count();

  std::cout << std::fixed << std::setprecision(2) << std::setw(13) << throughput
            << "k";
}

int main() {
  std::vector<std::size_t> block_sizes = {16, 64, 256, 1024, 8192, 16384};

  std::cout << "AES-256-ECB benchmark for " << _TEST_SECONDS << " seconds\n";
  std::cout << std::setw(14) << std::left << "type";
  for (auto blk : block_sizes)
    std::cout << std::right << std::setw(8) << blk << " bytes";
  std::cout << "\n";

  std::cout << std::setw(14) << std::left << "AES-256-ECB";
  std::cout << std::right;

  process_test<16>();
  process_test<64>();
  process_test<256>();
  process_test<1024>();
  process_test<8192>();
  process_test<16384>();

  std::cout << "\n";
  return 0;
}
