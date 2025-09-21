#include <iostream>

#include "algorithm/aes256.h"

int main() {
  file_encrypt::algorithm::AESByte byte = 0x57;
  file_encrypt::algorithm::AESByte result = 0x83 * byte;
  if (result == 0xc1) {
    return 0;
  }
  return -1;
}