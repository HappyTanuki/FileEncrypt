#include "algorithm/hmac.h"

#include "util/helper.h"

namespace file_encrypt::algorithm {

std::vector<std::byte> HMAC::Compute(std::vector<std::byte> key,
                                     const std::vector<std::byte>& data) const {
  if (key.size() > algorithm->inner_block_size / 8)
    key = algorithm->Digest({key, key.size() * 8}).digest;
  key.resize(algorithm->inner_block_size / 8, static_cast<std::byte>(0x00));
  std::vector<std::byte> inner_padding(algorithm->inner_block_size / 8,
                                       static_cast<std::byte>(0x36));
  std::vector<std::byte> outer_padding(algorithm->inner_block_size / 8,
                                       static_cast<std::byte>(0x5C));
  std::vector<std::byte> to_digest;
  to_digest = file_encrypt::util::XorVectors(key, inner_padding);
  to_digest = file_encrypt::util::ConcatByteVectors(to_digest, data);

  auto inner_hashed =
      algorithm->Digest({to_digest, to_digest.size() * 8}).digest;

  to_digest = file_encrypt::util::XorVectors(key, outer_padding);
  to_digest = file_encrypt::util::ConcatByteVectors(to_digest, inner_hashed);

  return algorithm->Digest({to_digest, to_digest.size() * 8}).digest;
}

void HMAC::Compute(const std::vector<std::byte>& data) {
  algorithm->Update({data, data.size() * 8});
}

std::vector<std::byte> HMAC::Finalize() {
  std::vector<std::byte> to_digest;
  auto inner_hashed = algorithm->Digest().digest;

  to_digest = file_encrypt::util::XorVectors(key, outer_padding);
  to_digest = file_encrypt::util::ConcatByteVectors(to_digest, inner_hashed);

  Reset();

  return algorithm->Digest({to_digest, to_digest.size() * 8}).digest;
}

};  // namespace file_encrypt::algorithm