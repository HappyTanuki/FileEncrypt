#ifndef FILE_ENCRYPT_UTIL_INCLUDE_UTIL_CPU_DETECT_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_UTIL_CPU_DETECT_H_
#include <cstdint>

namespace file_encrypt::util {

struct EdxEcx {
  std::uint32_t edx = 0;
  std::uint32_t ecx = 0;
};

EdxEcx GetCPUFeatures();

enum FeatureEDXBits {
  kFPU = 1 << 0,
  kVME = 1 << 1,
  kDE = 1 << 2,
  kPSE = 1 << 3,
  kTSC = 1 << 4,
  kMSR = 1 << 5,
  kPAE = 1 << 6,
  kMCE = 1 << 7,
  kCX8 = 1 << 8,
  kAPIC = 1 << 9,
  kSEP = 1 << 11,
  kMTRR = 1 << 12,
  kPGE = 1 << 13,
  kMCA = 1 << 14,
  kCMOV = 1 << 15,
  kPAT = 1 << 16,
  kPSE36 = 1 << 17,
  kPSN = 1 << 18,
  kCLFSH = 1 << 19,
  kDS = 1 << 21,
  kACPI = 1 << 22,
  kMMX = 1 << 23,
  kFXSR = 1 << 24,
  kSSE = 1 << 25,
  kSSE2 = 1 << 26,
  kSS = 1 << 27,
  kHTT = 1 << 28,
  kTM = 1 << 29,
  kIA64 = 1 << 30,
  kPBE = 1 << 31
};

enum FeatureECXBits {
  kSSE3 = 1 << 0,
  kPCLMULQDQ = 1 << 1,
  kDTES64 = 1 << 2,
  kMONITOR = 1 << 3,
  kDS_CPL = 1 << 4,
  kVMX = 1 << 5,
  kSMX = 1 << 6,
  kEST = 1 << 7,
  kTM2 = 1 << 8,
  kSSSE3 = 1 << 9,
  kCNXT_ID = 1 << 10,
  kSDBG = 1 << 11,
  kFMA = 1 << 12,
  kCMPXCHG16B = 1 << 13,
  kXTPR = 1 << 14,
  kPDCM = 1 << 15,
  kPCID = 1 << 17,
  kDCA = 1 << 18,
  kSSE4_1 = 1 << 19,
  kSSE4_2 = 1 << 20,
  kX2APIC = 1 << 21,
  kMOVBE = 1 << 22,
  kPOPCNT = 1 << 23,
  kTSC_DEADLINE = 1 << 24,
  kAESNI = 1 << 25,
  kXSAVE = 1 << 26,
  kOSXSAVE = 1 << 27,
  kAVX = 1 << 28,
  kF16C = 1 << 29,
  kRDRAND = 1 << 30,
  kHYPERVISOR = 1 << 31
};

}  // namespace file_encrypt::util

#endif