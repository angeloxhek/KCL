#define DEV
#include "KrnlCryptoLib.h"
#include "Masks.h"
#include "KCLUser.h"
#include <windows.h>
#include <winternl.h>
#include <intrin.h>

inline bool KCLCheckPEB1() {
#ifdef _WIN64
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
	PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
	return pPeb->BeingDebugged != 0;
}

inline bool KCLCheckPEB2() {
#ifdef _WIN64
	PPEB pPeb = (PPEB)__readgsqword(0x60);
	unsigned long ntGlobalFlag = *(unsigned long*)((unsigned char*)pPeb + 0xBC);
#else
	PPEB pPeb = (PPEB)__readfsdword(0x30);
	unsigned long ntGlobalFlag = *(unsigned long*)((unsigned char*)pPeb + 0x68);
#endif
	return (ntGlobalFlag & (0x10 | 0x20 | 0x40)) != 0;
}

static bool KCLCheckTiming() {
	volatile unsigned __int64 t1, t2;
	t1 = __rdtsc();
	for (volatile int i = 0; i < 5000; i++) {}
	t2 = __rdtsc();
	return (t2 - t1) > 100000;
}
static void KCLCleanupSafety() {
	size_t* p1 = GetKCLMagic1P();
	size_t* p2 = GetKCLMagic2P();
	size_t* p3 = GetKCLMagic3P();
	size_t* p4 = GetKCLMagic4P();
	size_t* p5 = GetKCLMagic5P();
	size_t* p6 = GetKCLMagic6P();
	*p1 ^= *p2;
	*p2 ^= *p3;
	*p3 ^= *p4;
	*p4 ^= *p5;
	*p5 ^= *p6;
	*p6 ^= (size_t)p1;
}

typedef PVOID(NTAPI* pfnRtlAddVectoredExceptionHandler)(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);

static constexpr DWORD KCLHashStringDJB2(const char* str) {
	DWORD hash = 5381;
	while (*str) {
		hash = ((hash << 5) + hash) + *str++;
	}
	return hash;
}

static DWORD KCLRuntimeHashDJB2(const char* str) {
	DWORD hash = 5381;
	while (*str) {
		hash = ((hash << 5) + hash) + *str++;
	}
	return hash;
}

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, * PMY_LDR_DATA_TABLE_ENTRY;

typedef struct _MY_PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} MY_PEB_LDR_DATA, * PMY_PEB_LDR_DATA;

PVOID GetProcAddressByHash(PVOID moduleBase, DWORD targetHash) {
	PBYTE pBase = (PBYTE)moduleBase;
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
	if (pNt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
	DWORD expRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (!expRVA) return nullptr;
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pBase + expRVA);
	PDWORD pNames = (PDWORD)(pBase + pExport->AddressOfNames);
	PDWORD pFuncs = (PDWORD)(pBase + pExport->AddressOfFunctions);
	PWORD pOrds = (PWORD)(pBase + pExport->AddressOfNameOrdinals);
	for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
		char* currentFuncName = (char*)(pBase + pNames[i]);
		if (KCLRuntimeHashDJB2(currentFuncName) == targetHash) {
			WORD ordinal = pOrds[i];
			return (PVOID)(pBase + pFuncs[ordinal]);
		}
	}
	return nullptr;
}

PVOID GetNtdllBase() {
#ifdef _WIN64
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
	PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

	PMY_PEB_LDR_DATA pLdr = (PMY_PEB_LDR_DATA)pPeb->Ldr;
	PLIST_ENTRY pHead = &pLdr->InLoadOrderModuleList;
	PLIST_ENTRY pFirst = pHead->Flink;
	PLIST_ENTRY pSecond = pFirst->Flink;

	PMY_LDR_DATA_TABLE_ENTRY pEntry = (PMY_LDR_DATA_TABLE_ENTRY)pSecond;
	return pEntry->DllBase;
}

LONG WINAPI KCLVEHHandler(EXCEPTION_POINTERS* pException) {
	PCONTEXT ctx = pException->ContextRecord;
	if (pException->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
		if (ctx->Rcx == KCL_VEH_MAGIC) {
			KCL_FUNC_ID funcId = (KCL_FUNC_ID)ctx->Rdx;
			void* pArgs = (void*)ctx->R8;
			size_t structSize = ctx->R9;
			if (pArgs != nullptr) {
				switch (funcId) {

				case FUNC_FILL_RAW_SEC_KEY:
					if (structSize == sizeof(KCLRawSecKeyArgs)) {
						auto args = (KCLRawSecKeyArgs*)pArgs;
						args->result = KCLFillRawSecKey(args->buff, args->key);
					}
					break;

				case FUNC_GET_SEC_KEY:
					if (structSize == sizeof(KCLSecKeyArgs)) {
						auto args = (KCLSecKeyArgs*)pArgs;
						args->result = KCLGetSecKey(args->input, args->output);
					}
					break;

				case FUNC_CRYPT_UA:
					if (structSize == sizeof(KCLCryptArgs)) {
						auto args = (KCLCryptArgs*)pArgs;
						args->result = KCLCryptUA((LPUSTR)args->input, args->len, args->key, (LPUSTR)args->output);
					}
					break;

				case FUNC_DECRYPT_UA:
					if (structSize == sizeof(KCLCryptArgs)) {
						auto args = (KCLCryptArgs*)pArgs;
						args->result = KCLDecryptUA((LPUSTR)args->input, args->len, args->key, (LPUSTR)args->output);
					}
					break;

				case FUNC_CRYPT_W:
					if (structSize == sizeof(KCLCryptArgs)) {
						auto args = (KCLCryptArgs*)pArgs;
						args->result = KCLCryptW((LPWSTR)args->input, args->len, args->key, (LPWSTR)args->output);
					}
					break;

				case FUNC_DECRYPT_W:
					if (structSize == sizeof(KCLCryptArgs)) {
						auto args = (KCLCryptArgs*)pArgs;
						args->result = KCLDecryptW((LPWSTR)args->input, args->len, args->key, (LPWSTR)args->output);
					}
					break;

				case FUNC_CRYPT_A:
					if (structSize == sizeof(KCLCryptArgs)) {
						auto args = (KCLCryptArgs*)pArgs;
						args->result = KCLCryptA((LPSTR)args->input, args->len, args->key, (LPSTR)args->output);
					}
					break;

				case FUNC_DECRYPT_A:
					if (structSize == sizeof(KCLCryptArgs)) {
						auto args = (KCLCryptArgs*)pArgs;
						args->result = KCLDecryptA((LPSTR)args->input, args->len, args->key, (LPSTR)args->output);
					}
					break;
				}
			}

			ctx->Rcx = 0;

			ctx->Rip += 2;

			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

void NTAPI tls_callback(PVOID DllHandle, DWORD dwReason, PVOID) {
	if (dwReason == DLL_PROCESS_ATTACH) {
		PVOID ntdllBase = GetNtdllBase();
		if (ntdllBase) {
			constexpr DWORD funcHash = KCLHashStringDJB2("RtlAddVectoredExceptionHandler");
			pfnRtlAddVectoredExceptionHandler MyRtlAddVectoredExceptionHandler =
				(pfnRtlAddVectoredExceptionHandler)GetProcAddressByHash(ntdllBase, funcHash);
			if (MyRtlAddVectoredExceptionHandler) {
				MyRtlAddVectoredExceptionHandler(1, KCLVEHHandler);
			}
		}

		bool isDebugged = KCLCheckPEB1() || KCLCheckPEB2() || KCLCheckTiming();

		if (isDebugged) {
			KCLCleanupSafety();
		}
	}
}

#ifdef _WIN64
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback_func")
#pragma const_seg(".CRT$XLF")
EXTERN_C const
#else
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback_func")
#pragma data_seg(".CRT$XLF")
EXTERN_C
#endif
PIMAGE_TLS_CALLBACK tls_callback_func = tls_callback;
#ifdef _WIN64
#pragma const_seg()
#else
#pragma data_seg()
#endif //_WIN64

#pragma optimize("", off)
static size_t GenKCLMagic(size_t mask) {
	volatile size_t a = mask ^ MAGICMASK;
	a = (a & ~3) | 1;
	while (a % 3 == 0 || a % 5 == 0 || a < (ULLONG_MAX / 4)) {
		a += 4;
		if (a < 4) a = 0x5;
	}
	return a;
}

static void KCLmemcpy(void* dest, const void* src, size_t count) {
	unsigned char* d = (unsigned char*)dest;
	const unsigned char* s = (const unsigned char*)src;
	while (count--) *d++ = *s++;
}
#pragma optimize("", on)

static UCHAR OpXor(UCHAR b, UCHAR m) { return b ^ m; }
static UCHAR OpAdd(UCHAR b, UCHAR m) { return b + m; }
static UCHAR OpRol(UCHAR b, UCHAR m) { return (b << (m % 8)) | (b >> (8 - (m % 8))); }

void KCLGetRecipe(size_t seed, KCLRecipe* recipe) {
	for (int i = 0; i < 8; i++) {
		size_t r = (seed >> i) % 3;
		if (r == 0) recipe->ops[i] = OpXor;
		else if (r == 1) recipe->ops[i] = OpAdd;
		else recipe->ops[i] = OpRol;

		recipe->masks[i] = (UCHAR)(seed >> (i * 2));
	}
}

UCHAR KCLApplyRecipe(UCHAR byte, KCLRecipe* recipe) {
	UCHAR res = byte;
	for (int i = 0; i < 8; i++) {
		res = recipe->ops[i](res, recipe->masks[i]);
	}
	return res;
}

bool KCLGetStrFromInt(LPANYCHAR buffer, size_t val, size_t len) {
	if (buffer == NULL) return false;

	KCLRecipe recipe;
	KCLGetRecipe(val, &recipe);

	LPUSTR pBuffer = (LPUSTR)buffer;
	size_t i = 1, k = 0;

	while (k < len) {
		size_t _ = val * i + i - 1;
		while (k < len) {
			UCHAR raw = (UCHAR)(_ % 255);

			pBuffer[k] = KCLApplyRecipe(raw, &recipe);

			_ /= 16;
			k++;
			if (_ <= 0) break;
		}
		i++;
	}

	return true;
}

bool KCLGetSecKey(LPKCLRSK input, LPKCLSK output) {
	if (input == NULL || output == NULL) return false;
	auto s = (input->x ^ input->y ^ input->z);
	auto ka = (input->a ^ s ^ GetKCLMagic4()) * GetKCLMagic3(),
		 kc = (size_t)(input->g & input->h ^ input->x) * GetKCLMagic3(),
		 kd = (input->c ^ s) * ((input->e & (0xFF << 3)) >> 3) * GetKCLMagic3(),
		 ke = (input->d ^ (s & 0b1000 ? input->x : (s & kc) ^ GetKCLMagic6())) * GetKCLMagic3();
	auto kb = (input->f ^ s) * GetKCLMagic5() & 0xFF;
	GETSECKEYMIX(ka); GETSECKEYMIX(kc); GETSECKEYMIX(kd); GETSECKEYMIX(ke);
	KCLGetStrFromInt(output->a, ka, 16);
	KCLGetStrFromInt(output->c, kc, 64);
	KCLGetStrFromInt(output->d, kd, 64);
	KCLGetStrFromInt(output->e, ke, 128);
	output->b = kb;
	return true;
}
UCHAR KCLEMaskCrypt(UCHAR byte, LPUSTR mask) {
	UCHAR p = mask[0] ^ mask[4] ^ mask[7],
		   res = byte ^ p,
		   s = (mask[1] + mask[5]) % 7 + 1;
	res = (res << s) | (res >> (8 - s));
	if (mask[2] % 2 == 0) {
		res = ~res;
	}
	res = res + mask[6];
	res = ((res & 0x0F) << 4) | ((res & 0xF0) >> 4);
	return res ^ mask[3];
}
UCHAR KCLEMaskDecrypt(UCHAR byte, LPUSTR mask) {
	UCHAR res = byte ^ mask[3];
	res = ((res & 0x0F) << 4) | ((res & 0xF0) >> 4);
	res = res - mask[6];
	if (mask[2] % 2 == 0) {
		res = ~res;
	}
	UCHAR s = (mask[1] + mask[5]) % 7 + 1;
	res = (res >> s) | (res << (8 - s));
	UCHAR p = mask[0] ^ mask[4] ^ mask[7];
	return res ^ p;
}
bool KCLCryptUA(LPUSTR input, size_t len, LPKCLSK key, LPUSTR output) {
	if (input == NULL || len == 0 || key == NULL || output == NULL) return false;
	for (size_t i = 0; i < len; i++) {
		UCHAR k = input[i];
		k ^= key->a[i % 16];
		UCHAR s = key->b % 8;
		k = (k << s) | (k >> (8 - s));
		k += key->c[i % 64];
		k ^= key->d[i % 64];
		k = KCLEMaskCrypt(k, &key->e[(i % 16) * 8]);
		output[i] = k;
	}
	return true;
}
bool KCLDecryptUA(LPUSTR input, size_t len, LPKCLSK key, LPUSTR output) {
	if (input == NULL || len == 0 || key == NULL || output == NULL) return false;
	for (size_t i = 0; i < len; i++) {
		UCHAR k = input[i];
		k = KCLEMaskDecrypt(k, &key->e[(i % 16) * 8]);
		k ^= key->d[i % 64];
		k -= key->c[i % 64];
		UCHAR s = key->b % 8;
		k = (k >> s) | (k << (8 - s));
		k ^= key->a[i % 16];
		output[i] = k;
	}
	return true;
}
size_t KCLUpdateRandomState(size_t* state) {
	*state = *state * GetKCLMagic1() + GetKCLMagic2();
	return *state;
}
bool KCLFillRawSecKey(LPKCLRSK buff, size_t key) {
	if (buff == NULL) return false;
	size_t t = key;
	buff->a = KCLUpdateRandomState(&t);
	buff->b = KCLUpdateRandomState(&t);
	buff->c = KCLUpdateRandomState(&t);
	buff->d = KCLUpdateRandomState(&t);
	buff->e = (UCHAR)(KCLUpdateRandomState(&t) & 0xFF);
	buff->f = (UCHAR)(KCLUpdateRandomState(&t) & 0xFF);
	buff->g = (UCHAR)(KCLUpdateRandomState(&t) & 0xFF);
	buff->h = (UCHAR)(KCLUpdateRandomState(&t) & 0xFF);
	buff->x = (unsigned)(KCLUpdateRandomState(&t) & 0xFFFFFFFF);
	buff->y = (unsigned)(KCLUpdateRandomState(&t) & 0xFFFFFFFF);
	buff->z = (unsigned)(KCLUpdateRandomState(&t) & 0xFFFFFFFF);
	return true;
}
bool KCLCryptW(LPWSTR input, size_t len, LPKCLSK key, LPWSTR output) {
	if (input == NULL || len == 0 || key == NULL || output == NULL) return false;
	return KCLCryptUA((LPUSTR)input, KCLUCharsInWCharsCount * len, key, (LPUSTR)output);
}
bool KCLDecryptW(LPWSTR input, size_t len, LPKCLSK key, LPWSTR output) {
	if (input == NULL || len == 0 || key == NULL || output == NULL) return false;
	return KCLDecryptUA((LPUSTR)input, KCLUCharsInWCharsCount * len, key, (LPUSTR)output);
}
bool KCLCryptA(LPSTR input, size_t len, LPKCLSK key, LPSTR output) {
	if (input == NULL || len == 0 || key == NULL || output == NULL) return false;
	return KCLCryptUA((LPUSTR)input, len, key, (LPUSTR)output);
}
bool KCLDecryptA(LPSTR input, size_t len, LPKCLSK key, LPSTR output) {
	if (input == NULL || len == 0 || key == NULL || output == NULL) return false;
	return KCLDecryptUA((LPUSTR)input, len, key, (LPUSTR)output);
}