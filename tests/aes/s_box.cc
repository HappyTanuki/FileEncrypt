#include <iostream>

#include "algorithm/block_cipher/aes.h"

int main() {
#ifdef _DEBUG
  file_encrypt::algorithm::AES<256> aes;
  file_encrypt::algorithm::AESByte byte = 0x53;

  const std::uint8_t* S_box = aes._Debug_get_S_box();

  if (S_box[byte] == 0xed) {
    return 0;
  }
  return -1;
#else
  return 0;
#endif
}