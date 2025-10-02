#include <iostream>

#include "algorithm/sha256.h"
#include "util/helper.h"

int main() {
  file_encrypt::algorithm::SHA256 hash;

  file_encrypt::algorithm::HashAlgorithmInputData input_data;
  input_data.message =
      file_encrypt::util::StrToBytes("https://namu.wiki/w/SHA");
  input_data.bit_length = input_data.message.size() * 8;

  hash.Update(input_data);
  auto result = hash.Digest();

  std::cout << file_encrypt::util::BytesToStr(result.digest) << std::endl;
}