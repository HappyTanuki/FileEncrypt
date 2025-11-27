#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BLOCK_CIPHER_MODE_BLOCK_CIPHER_MODES_FACTORY_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BLOCK_CIPHER_MODE_BLOCK_CIPHER_MODES_FACTORY_H_

#include "operation.h"

namespace file_encrypt::algorithm::op_mode {

template <std::uint32_t KeyBits>
std::unique_ptr<OperationMode<128, KeyBits, 1>> OPModeFactory(
    std::string name, const std::array<std::byte, KeyBits / 8>& key = {},
    const std::array<std::byte, 16>& iv = GetRandomArray<16>());
}

#include "block_cipher_modes_factory.inc"

#endif