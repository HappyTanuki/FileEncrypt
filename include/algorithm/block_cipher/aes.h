#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BLOCK_CIPHER_AES_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BLOCK_CIPHER_AES_H_

#include <array>

#include "algorithm/algorithm.h"

namespace file_encrypt::algorithm {

struct AESByte {
 public:
  constexpr AESByte() : value(0) {}
  constexpr AESByte(const std::uint8_t& byte) : value(byte) {}

  constexpr AESByte& operator=(const std::uint8_t& byte);
  constexpr AESByte& operator=(const std::byte& byte);

  constexpr AESByte operator<<(const int& n) const;
  constexpr AESByte operator>>(const int& n) const;

  constexpr AESByte& operator+=(const AESByte& byte);
  constexpr AESByte& operator-=(const AESByte& byte);
  constexpr AESByte& operator*=(const AESByte& byte);

  constexpr AESByte operator+(const AESByte& byte) const;
  constexpr AESByte operator-(const AESByte& byte) const;
  constexpr AESByte operator+(const int& byte) const;
  constexpr AESByte operator-(const int& byte) const;
  friend constexpr AESByte operator+(int lhs, const AESByte& byte);
  friend constexpr AESByte operator-(int lhs, const AESByte& byte);
  constexpr AESByte operator*(const int& byte) const;
  friend constexpr AESByte operator*(int lhs, const AESByte& byte);
  constexpr AESByte operator*(const AESByte& byte) const;

  constexpr operator std::uint8_t() const { return value; }
  constexpr operator std::byte() const { return static_cast<std::byte>(value); }

 private:
  std::uint8_t value = 0;

  constexpr AESByte xtime(const AESByte& byte) const;
};

struct AESMatrix {
 public:
  AESMatrix() = default;
  AESMatrix(std::array<std::array<AESByte, 4>, 4> value_) : value(value_) {}
  AESMatrix(std::initializer_list<std::initializer_list<AESByte>> init);
  constexpr AESMatrix operator*(const AESByte& scalar) const;
  friend constexpr AESMatrix operator*(AESByte lhs, const AESMatrix& matrix);

  constexpr AESMatrix operator*(const AESMatrix& matrix) const;
  constexpr AESMatrix operator+(const AESMatrix& matrix) const;

  std::array<AESByte, 4>& operator[](std::size_t row) { return value[row]; }
  const std::array<AESByte, 4>& operator[](std::size_t row) const {
    return value[row];
  }

  int rows = 4;
  int cols = 4;

 private:
  std::array<std::array<AESByte, 4>, 4> value = {0};
};

template <std::uint32_t KeyBits>
class AES : public BlockCipherAlgorithm {
 public:
  static_assert(KeyBits == 128 || KeyBits == 192 || KeyBits == 256,
                "AES key size must be 128, 192, or 256 bits");

  CipherAlgorithmReturnData Encrypt(
      const CipherAlgorithmInputData& data) const final override;
  CipherAlgorithmReturnData Decrypt(
      const CipherAlgorithmInputData& data) const final override;

#ifdef _DEBUG
  const std::uint8_t* _Debug_get_S_box() const { return S_box; }
#endif

 private:
  static constexpr std::uint32_t Nk = KeyBits / 32;
  static constexpr std::uint32_t Nr = Nk + 6;

  constexpr void KeyExpansion(
      const typename std::array<AESByte, 4 * Nk>& key,
      typename std::array<std::array<AESByte, 4>, 4 * (Nr + 1)>& expanded_key)
      const;

  constexpr void AddRoundKey(
      AESMatrix& state,
      const std::array<std::array<AESByte, 4>, 4 * (Nr + 1)>& round_key,
      const int& round) const;
  constexpr void InvMixColumns(AESMatrix& state) const;
  constexpr void InvShiftRows(AESMatrix& state) const;
  constexpr void InvSubBytes(AESMatrix& state) const;
  constexpr void MixColumns(AESMatrix& state) const;
  constexpr std::array<AESByte, 4> RotWord(
      const std::array<AESByte, 4>& bytes) const;
  constexpr void ShiftRows(AESMatrix& state) const;
  constexpr void SubBytes(AESMatrix& state) const;
  constexpr std::array<AESByte, 4> SubWord(
      const std::array<AESByte, 4>& bytes) const;
  constexpr std::array<AESByte, 4> Rcon(const std::uint32_t& i) const;

  static const std::uint8_t S_box[256];
  static const std::uint8_t Inv_S_box[256];
  static std::array<std::array<AESByte, 4>, 14> Rcon_memo;
  static int Rcon_memo_index;
};

};  // namespace file_encrypt::algorithm

// Implementation details only below here.

#include "aes256.inc"

#endif
