#pragma once
#ifndef KRNLCRYPTOLIB
#define KRNLCRYPTOLIB 1
#if defined(_WIN32) || defined(_WIN64)
#ifndef _WINNT_
typedef wchar_t WCHAR;
typedef char CHAR;
typedef wchar_t* LPWSTR;
typedef char* LPSTR;
#endif
#ifndef _MINWINDEF_
typedef unsigned char UCHAR;
#endif
#else
#include <stdint.h>
#include <stddef.h>
typedef uint16_t WCHAR;
typedef char CHAR;
typedef uint16_t* LPWSTR;
typedef char* LPSTR;
typedef unsigned char UCHAR;
#endif
typedef void* LPANYCHAR;
typedef UCHAR* LPUSTR;
typedef struct {
	size_t a, b, c, d;
	UCHAR e, f, g, h;
	unsigned x, y, z;
} KCLRawSecKey, KCLRSK, *LPKCLRSK;
typedef struct {
	UCHAR a[16], b, c[64], d[64], e[128];
} KCLSecKey, KCLSK, *LPKCLSK;
typedef UCHAR(*MaskOp)(UCHAR, UCHAR);
struct KCLRecipe {
	MaskOp ops[8];
	UCHAR  masks[8];
};
#define KCLUCharsInWCharsCount (sizeof(WCHAR) / sizeof(UCHAR))
static size_t GenKCLMagic(size_t);
void KCLGetRecipe(size_t, KCLRecipe*);
UCHAR KCLApplyRecipe(UCHAR, KCLRecipe*);
bool KCLGetStrFromInt(LPANYCHAR, size_t, size_t);
bool KCLGetSecKey(LPKCLRSK, LPKCLSK);
bool KCLCryptUA(LPUSTR, size_t, LPKCLSK, LPUSTR);
bool KCLDecryptUA(LPUSTR, size_t, LPKCLSK, LPUSTR);
bool KCLFillRawSecKey(LPKCLRSK, size_t);
bool KCLCryptW(LPWSTR, size_t, LPKCLSK, LPWSTR);
bool KCLDecryptW(LPWSTR, size_t, LPKCLSK, LPWSTR);
bool KCLCryptA(LPSTR, size_t, LPKCLSK, LPSTR);
bool KCLDecryptA(LPSTR, size_t, LPKCLSK, LPSTR);
#endif