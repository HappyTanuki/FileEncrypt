#include <iostream>

#include "algorithm/hash/sha.h"
#include "util/helper.h"

int main() {
  file_encrypt::algorithm::SHA<256> hash;

  file_encrypt::algorithm::HashAlgorithmInputData input_data;
  auto message = file_encrypt::util::StrToBytes("https://namu.wiki/w/SHA");
  input_data.message = message;
  input_data.bit_length = input_data.message.size() * 8;

  hash.Update(input_data);
  auto result = hash.Digest();

  std::cout << file_encrypt::util::BytesToHexStr(result) << std::endl;
}