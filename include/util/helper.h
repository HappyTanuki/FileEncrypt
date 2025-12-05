#ifndef FILE_ENCRYPT_UTIL_INCLUDE_UTIL_HELPER_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_UTIL_HELPER_H_

#include <cstring>
#include <iomanip>
#include <sstream>

namespace file_encrypt::util {

std::vector<std::byte> StrToBytes(const std::string& s);
std::string BytesToStr(const std::vector<std::byte>& bytes);

template <typename Container>
std::string BytesToHexStr(const Container& bytes);

std::vector<std::byte> HexStrToBytes(const std::string& hex);
template <std::uint32_t Size>
std::array<std::byte, Size> HexStrToBytes(const std::string& hex);

std::vector<std::byte> XorVectors(std::vector<std::byte> a,
                                  std::vector<std::byte> b);

template <std::uint32_t Size>
constexpr std::array<std::byte, Size> XorArrays(
    const std::array<std::byte, Size>& a, const std::array<std::byte, Size>& b);

template <std::uint32_t Size>
constexpr std::array<std::byte, Size> StandardIncrement(
    const std::array<std::byte, Size>& array, const int& m);

inline std::vector<std::byte> MaskSeedlen(const std::vector<std::byte>& v,
                                          const std::size_t seedlen_bits);

std::vector<std::byte> UInt8ToBytesVector(uint64_t value);
std::vector<std::byte> UInt32ToBytesVector(uint64_t value);

template <typename... Vectors>
std::vector<std::byte> AddByteVectors(const Vectors&... vecs);

template <typename... Vectors>
std::vector<std::byte> ConcatByteVectors(const Vectors&... vecs);

std::vector<std::byte> Leftmost(const std::vector<std::byte>& value,
                                const std::uint64_t& size);
std::vector<std::byte> Rightmost(const std::vector<std::byte>& value,
                                 const std::uint64_t& size);

std::string GetEnglishNumberSufix(std::uint64_t number);

std::string GetBasenameBeforeFirstDot(std::string filename);
std::string GetExtensionAfterFirstDot(std::string filename);

std::string GetCandidateName(std::string name_with_extention);
std::shared_ptr<std::ostream> OpenOStream(std::string name,
                                          bool overwrite = false,
                                          bool avoid = false);
std::shared_ptr<std::istream> OpenIStream(std::string name);

}  // namespace file_encrypt::util

#include "helper.inc"

#endif