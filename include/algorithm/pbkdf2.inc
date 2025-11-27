#include "pbkdf2.h"
#include "util/helper.h"

namespace file_encrypt::algorithm {

template <std::uint32_t Keylen>
std::array<std::byte, Keylen / 8> PBKDF2(std::string password,
                                         std::vector<std::byte> salt,
                                         std::weak_ptr<HMAC> hmac,
                                         std::uint64_t IterationCount) {
  std::array<std::byte, Keylen / 8> key = {};
  std::shared_ptr<HMAC> hmac_instance = hmac.lock();
  if (!hmac_instance) return key;
  if (Keylen > (4294967296 /*2^32*/ - 1) * hmac_instance->digest_size)
    return key;
  // 올림연산
  std::uint32_t len =
      ((Keylen + hmac_instance->digest_size - 1) / hmac_instance->digest_size);
  std::uint32_t r = Keylen - (len - 1) * hmac_instance->digest_size;
  std::vector<std::vector<std::byte>> T(len);
  std::vector<std::byte> U;
  for (std::uint32_t i = 1; i <= len; i++) {
    T[i - 1].clear();
    U = file_encrypt::util::ConcatByteVectors(
        salt, file_encrypt::util::UInt32ToBytesVector(i));
    for (std::uint32_t j = 1; j <= IterationCount; j++) {
      U = hmac_instance->Compute(file_encrypt::util::StrToBytes(password), U);
      T[i - 1] = file_encrypt::util::XorVectors(T[i - 1], U);
    }
  }
  T[len - 1] = file_encrypt::util::Leftmost(T[len - 1], r);

  std::vector<std::byte> concated_key;
  concated_key.reserve(Keylen / 8);
  for (std::uint32_t i = 1; i <= len; i++)
    concated_key.insert(concated_key.end(), T[i - 1].begin(), T[i - 1].end());

  std::memcpy(key.data(), concated_key.data(), Keylen / 8);
  return key;
}

}  // namespace file_encrypt::algorithm