#include "algorithm/block_cipher/mode/aliases.h"
#include "util/helper.h"

int main() {
  { // AES256_ECB
    file_encrypt::algorithm::AES256_ECB<10> cipher(
        file_encrypt::util::HexStringToBytes<32>(""));

    cipher << file_encrypt::util::HexStringToBytes("014730f80ac625fe84f026c60bfd547d");
    std::array<std::byte, 16> result;
    cipher >> result;
  }
}