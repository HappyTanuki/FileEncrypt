#include "hmac.h"
#include "util/helper.h"

namespace file_encrypt::algorithm {

template <std::uint32_t HashDigestLen>
std::vector<std::byte> HMAC<HashDigestLen>::Compute(
    std::vector<std::byte> key, const std::vector<std::byte>& data) const {
  if (key.size() > this->algorithm->inner_block_size / 8) {
    auto temp = this->algorithm->Digest({key, key.size() * 8});
    key = std::vector<std::byte>(temp.begin(), temp.end());
  }
  key.resize(algorithm->inner_block_size / 8, static_cast<std::byte>(0x00));
  std::vector<std::byte> inner_padding(algorithm->inner_block_size / 8,
                                       static_cast<std::byte>(0x36));
  std::vector<std::byte> outer_padding(algorithm->inner_block_size / 8,
                                       static_cast<std::byte>(0x5C));
  std::vector<std::byte> to_digest;
  to_digest = file_encrypt::util::XorVectors(key, inner_padding);
  to_digest = file_encrypt::util::ConcatByteVectors(to_digest, data);

  auto inner_hashed = algorithm->Digest({to_digest, to_digest.size() * 8});

  to_digest = file_encrypt::util::XorVectors(key, outer_padding);
  to_digest = file_encrypt::util::ConcatByteVectors(to_digest, inner_hashed);

  auto digest = algorithm->Digest({to_digest, to_digest.size() * 8});

  return std::vector<std::byte>(digest.begin(), digest.end());
}

template <std::uint32_t HashDigestLen>
void HMAC<HashDigestLen>::Compute(const std::vector<std::byte>& data) {
  algorithm->Update({data, data.size() * 8});
}

template <std::uint32_t HashDigestLen>
std::vector<std::byte> HMAC<HashDigestLen>::Finalize() {
  std::vector<std::byte> to_digest;
  auto inner_hashed = algorithm->Digest();

  to_digest = file_encrypt::util::XorVectors(key, outer_padding);
  to_digest = file_encrypt::util::ConcatByteVectors(to_digest, inner_hashed);

  Reset();

  auto digest = algorithm->Digest({to_digest, to_digest.size() * 8});

  return std::vector<std::byte>(digest.begin(), digest.end());
}

};  // namespace file_encrypt::algorithm