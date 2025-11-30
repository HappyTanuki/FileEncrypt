#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_ALGORITHM_FACTORY_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_ALGORITHM_FACTORY_H_

#include <memory>

#include "algorithm.h"
#include "block_cipher/mode/operation.h"

namespace file_encrypt::algorithm {

template <std::uint32_t DigestLen>
std::unique_ptr<HashAlgorithm<DigestLen>> HashFactory(std::string name);

}

namespace file_encrypt::algorithm::op_mode {

template <std::uint32_t KeyBits>
std::unique_ptr<OperationMode<128, KeyBits, 1>> OPModeFactory(
    std::string name, const std::array<std::byte, KeyBits / 8>& key = {},
    const std::array<std::byte, 16>& iv = GetRandomArray<16>());

}

#include "block_cipher_modes_factory.inc"
#include "hash_factory.inc"

#endif