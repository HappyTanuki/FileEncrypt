#include "util/cpu_detect.h"

#ifndef _WIN32
#include <cpuid.h>
#else
#include <intrin.h>
#endif

namespace file_encrypt::util {

EdxEcx GetCPUFeatures() {
  EdxEcx features;
#ifndef _WIN32
  std::uint32_t eax, ebx;
  __get_cpuid(1, &eax, &ebx, &features.ecx, &features.edx);
  return features;
#else
  int cpuInfo[4] = {0};
  __cpuid(cpuInfo, 1);
  features.edx = static_cast<std::uint32_t>(cpuInfo[3]);
  features.ecx = static_cast<std::uint32_t>(cpuInfo[2]);
  return features;
#endif
}

}  // namespace file_encrypt::util
