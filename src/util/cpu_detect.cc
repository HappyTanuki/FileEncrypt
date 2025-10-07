#include "util/cpu_detect.h"

#include <cpuid.h>

namespace file_encrypt::util {

EdxEcx GetCPUFeatures() {
  EdxEcx features;
  std::uint32_t eax, ebx;
  __get_cpuid(1, &eax, &ebx, &features.ecx, &features.edx);
  return features;
}

}  // namespace file_encrypt::util