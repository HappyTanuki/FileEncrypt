#include <cstring>

#include "aes.h"
#include "util/cpu_detect.h"

namespace file_encrypt::algorithm {

constexpr AESByte& AESByte::operator=(const std::uint8_t& byte) {
  value = byte;
  return *this;
}
constexpr AESByte& AESByte::operator=(const std::byte& byte) {
  value = static_cast<std::uint8_t>(byte);
  return *this;
}

constexpr AESByte AESByte::operator<<(const int& n) const {
  return AESByte(value << n);
}
constexpr AESByte AESByte::operator>>(const int& n) const {
  return AESByte(value >> n);
}

constexpr AESByte& AESByte::operator+=(const AESByte& byte) {
  *this = *this + byte;
  return *this;
}
constexpr AESByte& AESByte::operator-=(const AESByte& byte) {
  *this = *this - byte;
  return *this;
}
constexpr AESByte& AESByte::operator*=(const AESByte& byte) {
  *this = *this * byte;
  return *this;
}

constexpr AESByte AESByte::operator+(const AESByte& byte) const {
  return AESByte(this->value ^ byte.value);
}
constexpr AESByte AESByte::operator-(const AESByte& byte) const {
  return *this + byte;
}
constexpr AESByte AESByte::operator+(const int& byte) const {
  return *this + AESByte(byte);
}
constexpr AESByte AESByte::operator-(const int& byte) const {
  return *this - AESByte(byte);
}
constexpr AESByte operator+(int lhs, const AESByte& byte) {
  return AESByte(lhs) + byte;
}
constexpr AESByte operator-(int lhs, const AESByte& byte) {
  return AESByte(lhs) - byte;
}
constexpr AESByte AESByte::operator*(const int& byte) const {
  return *this * AESByte(byte);
}
constexpr AESByte operator*(int lhs, const AESByte& byte) {
  return AESByte(lhs) * byte;
}
// naive implementation
// constexpr AESByte AESByte::operator*(const AESByte& byte) const {
//   AESByte result = 0, state = *this;

//   for (int i = 0; i < 8; i++) {
//     if ((static_cast<std::uint8_t>(byte) >> i) & 0b1) {
//       result += state;
//     }
//     state = xtime(state);
//   }

//   return result;
// }
constexpr AESByte AESByte::operator*(const AESByte& byte) const {
  return AESByte(mul_table[this->value][byte.value]);
}
constexpr AESByte AESByte::xtime(const AESByte& byte) const {
  AESByte result = byte << 1;
  if (static_cast<std::uint8_t>(byte) & 0x80) {
    result -= 0x1b;
  }
  return result;
}

AESMatrix::AESMatrix(
    std::initializer_list<std::initializer_list<AESByte>> init) {
  int i = 0;
  for (auto& row : init) {
    int j = 0;
    for (auto& val : row) {
      value[i][j++] = val;
    }
    i++;
  }
}
constexpr AESMatrix AESMatrix::operator*(const AESByte& scalar) const {
  AESMatrix result;

  for (int i = 0; i < rows; i++) {
    for (int j = 0; j < cols; j++) {
      result.value[i][j] = value[i][j] * scalar;
    }
  }

  return result;
}
constexpr AESMatrix operator*(AESByte lhs, const AESMatrix& matrix) {
  return matrix * lhs;
}

constexpr AESMatrix AESMatrix::operator*(const AESMatrix& matrix) const {
  AESMatrix result;

  if (cols != matrix.rows) {
    return result;
  }

  for (int i = 0; i < rows; i++) {
    for (int j = 0; j < matrix.cols; j++) {
      for (int k = 0; k < cols; k++) {
        result.value[i][j] += value[i][k] * matrix.value[k][j];
      }
    }
  }

  result.rows = rows;
  result.cols = matrix.cols;

  return result;
}

constexpr AESMatrix AESMatrix::operator+(const AESMatrix& matrix) const {
  AESMatrix result;

  if (rows != matrix.rows || cols != matrix.cols) {
    return result;
  }

  for (int i = 0; i < rows; i++) {
    for (int j = 0; j < cols; j++) {
      result.value[i][j] = value[i][j] + matrix.value[i][j];
    }
  }

  return result;
}

template <std::uint32_t KeyBits>
AES<KeyBits>::AES() {
  file_encrypt::util::EdxEcx features = file_encrypt::util::GetCPUFeatures();
  cpu_aes_ni = features.ecx & file_encrypt::util::FeatureECXBits::kAESNI;
  cpu_sse2 = features.edx & file_encrypt::util::FeatureEDXBits::kSSE2;
}

template <std::uint32_t KeyBits>
CipherAlgorithmReturnData AES<KeyBits>::Encrypt(
    const CipherAlgorithmInputData& data) const {
  if (data.data.size() != 16 || data.key.size() != KeyBits / 8) {
    return CipherAlgorithmReturnData();
  }

  auto data_iter = data.data.begin();
  auto key_iter = data.key.begin();
  AESMatrix state;
  std::array<AESByte, 4 * Nk> key;
  std::array<std::array<AESByte, 4>, 4 * (Nr + 1)> expanded_key;

  for (int j = 0; j < 4; j++) {
    for (int i = 0; i < 4; i++) {
      state[i][j] = *data_iter++;
    }
  }

  for (int i = 0; i < 4 * Nk; i++) {
    key[i] = *key_iter++;
  }

  KeyExpansion(key, expanded_key);

  AddRoundKey(state, expanded_key, 0);

  for (int round = 1; round < Nr; round++) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, expanded_key, round);
  }
  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(state, expanded_key, Nr);

  CipherAlgorithmReturnData return_data;
  return_data.data.resize(16);
  auto return_data_iter = return_data.data.begin();

  for (int j = 0; j < 4; j++) {
    for (int i = 0; i < 4; i++) {
      *return_data_iter++ = state[i][j];
    }
  }

  return return_data;
}
template <std::uint32_t KeyBits>
CipherAlgorithmReturnData AES<KeyBits>::Decrypt(
    const CipherAlgorithmInputData& data) const {
  if (data.data.size() != 16 || data.key.size() != KeyBits / 8) {
    return CipherAlgorithmReturnData();
  }

  auto data_iter = data.data.begin();
  auto key_iter = data.key.begin();
  AESMatrix state;
  std::array<AESByte, 4 * Nk> key;
  std::array<std::array<AESByte, 4>, 4 * (Nr + 1)> expanded_key;

  for (int j = 0; j < 4; j++) {
    for (int i = 0; i < 4; i++) {
      state[i][j] = *data_iter++;
    }
  }

  for (int i = 0; i < 4 * Nk; i++) {
    key[i] = *key_iter++;
  }

  KeyExpansion(key, expanded_key);

  AddRoundKey(state, expanded_key, Nr);

  for (int round = Nr - 1; round > 0; round--) {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, expanded_key, round);
    InvMixColumns(state);
  }
  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(state, expanded_key, 0);

  CipherAlgorithmReturnData return_data;
  return_data.data.resize(16);
  auto return_data_iter = return_data.data.begin();

  for (int j = 0; j < 4; j++) {
    for (int i = 0; i < 4; i++) {
      *return_data_iter++ = state[i][j];
    }
  }

  return return_data;
}

template <std::uint32_t KeyBits>
constexpr void AES<KeyBits>::KeyExpansion(
    const typename std::array<AESByte, 4 * Nk>& key,
    typename std::array<std::array<AESByte, 4>, 4 * (Nr + 1)>& expanded_key)
    const {
  std::array<AESByte, 4> temp;

  if (cpu_sse2 && cpu_aes_ni) {
    //   __m128i round_keys[Nr + 1];
    //   while (i < 4 * (Nr + 1)) {
    //     __m128i temp = _mm_loadu_si128(
    //         reinterpret_cast<const __m128i*>(expanded_key[i - 1].data()));

    //     temp = _mm_aeskeygenassist_si128(temp, 0x01 << ((i / Nk) - 1));

    //     i++;
    //   }
    // } else {
    int i = 0;

    for (i = 0; i < Nk; i++) {
      std::memcpy(expanded_key[i].data(), key.data() + (i * 4), 4);
    }
    while (i < 4 * (Nr + 1)) {
      std::memcpy(temp.data(), expanded_key.data() + (i - 1), 4);

      if (i % Nk == 0) {
        temp = SubWord(RotWord(temp));

        __m128i temp2 =
            _mm_loadu_si64(reinterpret_cast<const __m64*>(temp.data()));
        __m128i temp3 =
            _mm_loadu_si64(reinterpret_cast<const __m64*>(Rcon(i / Nk).data()));
        __m128i temp4 = _mm_xor_si128(temp2, temp3);
        _mm_storeu_si32(reinterpret_cast<__m128i*>(temp.data()), temp4);

        // equivalent to:
        // temp[0] += Rcon(i / Nk)[0];
        // temp[1] += Rcon(i / Nk)[1];
        // temp[2] += Rcon(i / Nk)[2];
        // temp[3] += Rcon(i / Nk)[3];
      } else if (Nk > 6 && i % Nk == 4) {
        temp = SubWord(temp);
      }
      __m128i temp2 =
          _mm_loadu_si64(reinterpret_cast<const __m64*>(temp.data()));
      __m128i temp3 = _mm_loadu_si64(
          reinterpret_cast<const __m64*>(expanded_key[i - Nk].data()));
      __m128i temp4 = _mm_xor_si128(temp2, temp3);
      _mm_storeu_si32(reinterpret_cast<__m128i*>(expanded_key[i].data()),
                      temp4);

      // equivalent to:
      // expanded_key[i][0] = expanded_key[i - Nk][0] + temp[0];
      // expanded_key[i][1] = expanded_key[i - Nk][1] + temp[1];
      // expanded_key[i][2] = expanded_key[i - Nk][2] + temp[2];
      // expanded_key[i][3] = expanded_key[i - Nk][3] + temp[3];

      i++;
    }
  }
}

template <std::uint32_t KeyBits>
constexpr void AES<KeyBits>::AddRoundKey(
    AESMatrix& state,
    const std::array<std::array<AESByte, 4>, 4 * (Nr + 1)>& round_key,
    const int& round) const {
  for (int col = 0; col < 4; col++) {
    for (int row = 0; row < 4; row++) {
      state[row][col] += round_key[round * 4 + col][row];
    }
  }
}
template <std::uint32_t KeyBits>
constexpr void AES<KeyBits>::InvMixColumns(AESMatrix& state) const {
  AESMatrix a = {{0x0e, 0x0b, 0x0d, 0x09},
                 {0x09, 0x0e, 0x0b, 0x0d},
                 {0x0d, 0x09, 0x0e, 0x0b},
                 {0x0b, 0x0d, 0x09, 0x0e}};
  AESMatrix column;
  column.cols = 1;

  for (int col = 0; col < 4; col++) {
    for (int row = 0; row < 4; row++) {
      column[row][0] = state[row][col];
    }

    column = a * column;

    for (int row = 0; row < 4; row++) {
      state[row][col] = column[row][0];
    }
  }
}
template <std::uint32_t KeyBits>
constexpr void AES<KeyBits>::InvShiftRows(AESMatrix& state) const {
  AESMatrix shifted;

  for (int row = 0; row < 4; row++) {
    for (int col = 0; col < 4; col++) {
      shifted[row][(col + row) % 4] = state[row][col];
    }
  }

  state = shifted;
}
// 캐시 타이밍 공격에 취약함
// 하지만 해결 방법을 이해할 수 없기에 적용하지 않았음
template <std::uint32_t KeyBits>
constexpr void AES<KeyBits>::InvSubBytes(AESMatrix& state) const {
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      state[i][j] = Inv_S_box[state[i][j]];
    }
  }
}
template <std::uint32_t KeyBits>
constexpr void AES<KeyBits>::MixColumns(AESMatrix& state) const {
  AESMatrix a = {{0x02, 0x03, 0x01, 0x01},
                 {0x01, 0x02, 0x03, 0x01},
                 {0x01, 0x01, 0x02, 0x03},
                 {0x03, 0x01, 0x01, 0x02}};
  AESMatrix column;
  column.cols = 1;

  for (int col = 0; col < 4; col++) {
    for (int row = 0; row < 4; row++) {
      column[row][0] = state[row][col];
    }

    column = a * column;

    for (int row = 0; row < 4; row++) {
      state[row][col] = column[row][0];
    }
  }
}
template <std::uint32_t KeyBits>
constexpr std::array<AESByte, 4> AES<KeyBits>::RotWord(
    const std::array<AESByte, 4>& bytes) const {
  std::array<AESByte, 4> result = {0};

  result[0] = bytes[1];
  result[1] = bytes[2];
  result[2] = bytes[3];
  result[3] = bytes[0];

  return result;
}
template <std::uint32_t KeyBits>
constexpr void AES<KeyBits>::ShiftRows(AESMatrix& state) const {
  AESMatrix shifted;

  for (int row = 0; row < 4; row++) {
    for (int col = 0; col < 4; col++) {
      shifted[row][col] = state[row][(col + row) % 4];
    }
  }

  state = shifted;
}
// 캐시 타이밍 공격에 취약함
// 하지만 해결 방법을 이해할 수 없기에 적용하지 않았음
template <std::uint32_t KeyBits>
constexpr void AES<KeyBits>::SubBytes(AESMatrix& state) const {
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      state[i][j] = S_box[state[i][j]];
    }
  }
}
// 캐시 타이밍 공격에 취약함
// 하지만 해결 방법을 이해할 수 없기에 적용하지 않았음
template <std::uint32_t KeyBits>
constexpr std::array<AESByte, 4> AES<KeyBits>::SubWord(
    const std::array<AESByte, 4>& bytes) const {
  std::array<AESByte, 4> result;

  for (int i = 0; i < 4; i++) {
    result[i] = S_box[bytes[i]];
  }

  return result;
}
template <std::uint32_t KeyBits>
constexpr std::array<AESByte, 4> AES<KeyBits>::Rcon(
    const std::uint32_t& i) const {
  if (Rcon_memo[i][0] != 0x00) {
    return Rcon_memo[i];
  }

  for (int j = Rcon_memo_index + 1; j <= i; j++) {
    Rcon_memo[j][0] = Rcon_memo[j - 1][0] * 0x02;
  }
  Rcon_memo_index = i;

  return Rcon_memo[i];
}

template <std::uint32_t KeyBits>
const std::uint8_t AES<KeyBits>::S_box[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

template <std::uint32_t KeyBits>
const std::uint8_t AES<KeyBits>::Inv_S_box[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d};

template <std::uint32_t KeyBits>
std::array<std::array<AESByte, 4>, 14> AES<KeyBits>::Rcon_memo = {{
    {0x00, 0x00, 0x00, 0x00},
    {0x01, 0x00, 0x00, 0x00},
}};

template <std::uint32_t KeyBits>
int AES<KeyBits>::Rcon_memo_index = 1;

const std::array<std::array<std::uint8_t, 256>, 256> AESByte::mul_table =
    AESByte::generate_LUT();
};  // namespace file_encrypt::algorithm