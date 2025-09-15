#include "algorithm/sha256.h"

#include "precomp.h"

int main() {
  file_encrypt::algorithm::SHA256 sha256;
  file_encrypt::algorithm::HashAlgorithmInputData input_data;
  // Fill input_data with your test data
  file_encrypt::algorithm::HashAlgorithmReturnData result =
      sha256.Digest(input_data);

  std::cout << "SHA-256 Digest: ";
  for (int i = 0; i < 32; i++) {
    std::cout << std::hex << std::to_integer<int>(result.digest[i]);
  }
  std::cout << std::endl;

  return 0;
}