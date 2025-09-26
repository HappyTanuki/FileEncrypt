#ifndef FILE_ENCRYPT_UTIL_INCLUDE_IO_STREAM_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_IO_STREAM_H_
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <vector>

#include "algorithm/algorithm.h"

namespace file_encrypt::io {

struct BitlengthModifier {
  std::uint64_t len;
};

BitlengthModifier Len(std::uint64_t len_) { return {len_}; }

class EncodingStream {
 public:
  EncodingStream(
      std::unique_ptr<file_encrypt::algorithm::HashAlgorithm>&& encoder);
  EncodingStream(
      std::unique_ptr<file_encrypt::algorithm::BlockCipherAlgorithm>&& encoder);

  EncodingStream& operator<<(const BitlengthModifier& length);
  EncodingStream& operator<<(const std::vector<std::byte>& data);
  EncodingStream& operator<<(const std::filesystem::path& file_path);

  EncodingStream& operator>>(std::vector<std::byte>& data);

 private:
  void ClearEncoder();

  BitlengthModifier bitlength = {};

  std::unique_ptr<file_encrypt::algorithm::HashAlgorithm> hash_encoder;
  std::unique_ptr<file_encrypt::algorithm::BlockCipherAlgorithm> cipher_encoder;

  std::vector<std::byte> result;
};

}  // namespace file_encrypt::io
#endif