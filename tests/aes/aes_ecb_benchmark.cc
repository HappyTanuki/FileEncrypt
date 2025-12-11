#include <array>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>

#include "algorithm/block_cipher/mode/aliases.h"
#include "algorithm/csprng/csprng.h"

#define _KEY_BIT 256
#define _ALGORITHM file_encrypt::algorithm::AES_ECB<_KEY_BIT>
#define _BLOCK_SIZE 16     // AES block size in bytes
#define _TEST_SECONDS 10L  // 반복 측정 시간

int main() {
  std::cout << "Generating random data for blocks..." << std::endl;
  // 1. AES block buffer 생성 및 랜덤 초기화
  std::vector<std::array<std::byte, _BLOCK_SIZE>> block(70000);
  for (std::uint64_t i = 0; i < block.size(); i++) {
    file_encrypt::algorithm::CSPRNG::GetRandom(
        reinterpret_cast<char*>(block[i].data()), _BLOCK_SIZE);
  }

  _ALGORITHM cipher;

  // 2. 반복 시작
  const std::uint64_t CHECK_INTERVAL = 10000;
  std::uint64_t iterations = 0;
  auto start_time = std::chrono::high_resolution_clock::now();
  auto end_time = start_time;

  while (true) {
    for (std::uint64_t i = 0; i < CHECK_INTERVAL; i++) {
      cipher << block[iterations % block.size()];
      iterations++;
    }
    end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<long double> elapsed = end_time - start_time;
    if (elapsed.count() >= _TEST_SECONDS) break;
  }

  // 3. elapsed time 계산
  std::chrono::duration<long double> elapsed = end_time - start_time;

  // 4. throughput 계산
  long double bytes_processed =
      static_cast<long double>(_BLOCK_SIZE) * iterations;
  long double kb_processed = bytes_processed / 1024.0L;
  long double throughput = kb_processed / elapsed.count();

  // 5. 출력
  std::cout << std::fixed << std::setprecision(2);
  std::cout << "Elapsed time: " << elapsed.count() << " seconds\n";
  std::cout << "blocks processed: " << iterations << "\n";
  std::cout << "bytes processed: " << kb_processed << "kb\n";
  std::cout << "throughput: " << throughput << "kb/s\n";

  return 0;
}
