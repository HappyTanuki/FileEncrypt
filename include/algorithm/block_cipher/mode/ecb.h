#include "operation.h"

namespace file_encrypt::algorithm::op_mode {

template <std::uint32_t BlockSizeBits, std::uint32_t KeyBits,
          std::uint32_t BufferSize>
class ECB : public OperationMode {
 public:
  constexpr ECB& operator<<(const std::vector<std::byte>& data) final;
  constexpr ECB& operator>>(const std::vector<std::byte>& data) final;
};

};  // namespace file_encrypt::algorithm::op_mode