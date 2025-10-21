#ifndef FILE_ENCRYPT_UTIL_INCLUDE_UTIL_HELPER_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_UTIL_HELPER_H_

#include <iomanip>
#include <sstream>
#include <string>

namespace file_encrypt::util {

constexpr std::vector<std::byte> StrToBytes(const std::string& s);

template <typename Container>
std::string BytesToStr(const Container& bytes);

constexpr std::vector<std::byte> HexStringToBytes(const std::string& hex);
template <std::uint32_t Size>
constexpr std::array<std::byte, Size> HexStringToBytes(const std::string& hex);

constexpr std::vector<std::byte> XorVectors(const std::vector<std::byte>& a,
                                            const std::vector<std::byte>& b);

template <std::uint32_t Size>
constexpr std::array<std::byte, Size> XorArrays(
    const std::array<std::byte, Size>& a, const std::array<std::byte, Size>& b);

template <std::uint32_t Size>
constexpr std::array<std::byte, Size> StandardIncrement(
    const std::array<std::byte, Size>& array, const int& m);

}  // namespace file_encrypt::util

#include "helper.inc"

#endif