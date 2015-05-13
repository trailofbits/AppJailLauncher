// common.h : include file for macros common across all source files

#pragma once

#define NETWORK_ACCESS_CAPABILITY  _T("S-1-15-3-1")

#define PRINT(fmt, ...) { \
	_tprintf(_T(fmt), __VA_ARGS__); \
}
#define ALLOC(c)       HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, c)
#define REALLOC(p, c)  HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, p, c)
#define FREE(p)        HeapFree(GetProcessHeap(), 0, (LPVOID) p)

#ifdef _DEBUG
#define LOG(fmt, ...) { \
	_tprintf(_T("<*> ") _T(fmt), __VA_ARGS__); \
}
#define ERR(fmt, ...) { \
	_tprintf(_T("[%s:%i] <!> \n"), _T(__FILE__), __LINE__); \
	_tprintf(_T(fmt), __VA_ARGS__); \
}
#define ASSERT(cond, label) { \
	if (!(cond)) { \
		ERR("Assertion failed.\n"); \
		_tprintf(_T("  (%s) resolved to FALSE.\n"), _T(#cond)); \
		goto label; \
	} \
}
#define W32_ASSERT(cond, label) { \
	if (!(cond)) { \
		ERR("Assertion failed. GetLastError() = %i\n", GetLastError()); \
		_tprintf(_T("  (%s) resolved to FALSE.\n"), _T(#cond)); \
		goto label; \
	} else { \
		LOG("Assertion success!\n"); \
		_tprintf(_T("  (%s) succeeded.\n"), _T(#cond)); \
	} \
}
#define WS2_ASSERT(cond, label) { \
	if (!(cond)) { \
		ERR("Assertion failed. WSAGetLastError() = %i\n", WSAGetLastError()); \
		_tprintf(_T("  (%s) resolved to FALSE.\n"), _T(#cond)); \
		goto label; \
	} else { \
		LOG("Assertion success!\n"); \
		_tprintf(_T("  (%s) succeeded.\n"), _T(#cond)); \
	} \
}
#else
#define LOG(f, ...)
#define ERR(f, ...)
#define ASSERT(cond, label) { \
	if (!(cond)) { \
		goto label; \
	} \
}
#define W32_ASSERT  ASSERT
#define WS2_ASSERT  ASSERT
#endif