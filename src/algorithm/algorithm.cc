#include "algorithm/algorithm.h"

#ifdef _WIN32
extern "C" __declspec(dllexport) void dummy_export_function() {
  for (int i = 0; i < 10; i++) {
    i++;
  }
  return;
}
#endif
