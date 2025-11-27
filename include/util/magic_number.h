#ifndef FILE_ENCRYPT_UTIL_INCLUDE_UTIL_MAGIC_NUMBER_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_UTIL_MAGIC_NUMBER_H_

#include <array>

#include "util/helper.h"

namespace file_encrypt::util {

const std::array<std::byte, 4> NoPasswordKey =
    util::HexStrToBytes<4>("A74F000F");
const std::array<std::byte, 4> PasswordCombinedKey =
    util::HexStrToBytes<4>("A74F010F");
const std::array<std::byte, 4> PasswordOnlyKey =
    util::HexStrToBytes<4>("A74F020F");

}  // namespace file_encrypt::util

#endif