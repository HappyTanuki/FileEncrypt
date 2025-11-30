#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_PBKDF_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_PBKDF_H_
#include "mac/hmac.h"

namespace file_encrypt::algorithm {

struct PBKDF2ReturnData {
  ReturnStatus status = ReturnStatus::kERROR_FLAG;
  std::vector<std::byte> mk = {};
};

// NIST SP 800-132는 IterationCount에 최소 1000을 권장하지만 추가 서술로
// 1000000번, 다른 알고리즘들 ex) PBKDF2-SHA<256>은 600000회 정도를 추천하고
// 있으므로 적당히 조절할 것.
// https://csrc.nist.gov/csrc/media/Projects/crypto-publication-review-project/documents/initial-comments/sp800-132-initial-public-comments-2023.pdf
// 7 페이지 참고
// 주어진 비밀번호와 솔트로 키를 생성한다
template <std::uint32_t HashDigestLen, std::uint32_t Keylen>
std::array<std::byte, Keylen / 8> PBKDF2(
    std::string password, std::vector<std::byte> salt,
    std::weak_ptr<HMAC<HashDigestLen>> hmac_algorithm,
    std::uint64_t IterationCount = 1000);

}  // namespace file_encrypt::algorithm

#include "pbkdf2.inc"

#endif