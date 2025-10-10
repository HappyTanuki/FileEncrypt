#ifndef FILE_ENCRYPT_UTIL_INCLUDE_PRECOMP_H
#define FILE_ENCRYPT_UTIL_INCLUDE_PRECOMP_H
#if _WIN32
	#include <winsock2.h>
#else
	#include <arpa/inet.h>
#endif
#include <immintrin.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

#if _WIN32
	// because microsoft smart app control blocks
	#define _USE_SIMD_INTRINSIC false 
#else
	#define _USE_SIMD_INTRINSIC true
#endif

#endif