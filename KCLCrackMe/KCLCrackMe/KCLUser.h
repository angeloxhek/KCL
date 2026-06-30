#pragma once
#include "KrnlCryptoLib.h"

#define KCL_VEH_MAGIC 0xDEADBEEFC0DEFACE

enum KCL_FUNC_ID : size_t {
    FUNC_GET_SEC_KEY = 1,
    FUNC_FILL_RAW_SEC_KEY,
    FUNC_CRYPT_UA,
    FUNC_DECRYPT_UA,
    FUNC_CRYPT_W,
    FUNC_DECRYPT_W,
    FUNC_CRYPT_A,
    FUNC_DECRYPT_A
};

struct KCLRawSecKeyArgs {
    LPKCLRSK buff;
    size_t key;
    bool result;
};

struct KCLSecKeyArgs {
    LPKCLRSK input;
    LPKCLSK output;
    bool result;
};

struct KCLCryptArgs {
    void* input;
    size_t len;
    LPKCLSK key;
    void* output;
    bool result;
};

#ifndef DEV
typedef UCHAR* LPUSTR;
extern "C" void KCLStdCall(size_t magic, size_t funcId, void* pArgs, size_t size);

inline bool KCLFillRawSecKey(LPKCLRSK buff, size_t key) {
    KCLRawSecKeyArgs args = { buff, key, false };
    KCLStdCall(KCL_VEH_MAGIC, FUNC_FILL_RAW_SEC_KEY, &args, sizeof(args));
    return args.result;
}

inline bool KCLGetSecKey(LPKCLRSK input, LPKCLSK output) {
    KCLSecKeyArgs args = { input, output, false };
    KCLStdCall(KCL_VEH_MAGIC, FUNC_GET_SEC_KEY, &args, sizeof(args));
    return args.result;
}

inline bool KCLCryptUA(LPUSTR input, size_t len, LPKCLSK key, LPUSTR output) {
    KCLCryptArgs args = { input, len, key, output, false };
    KCLStdCall(KCL_VEH_MAGIC, FUNC_CRYPT_UA, &args, sizeof(args));
    return args.result;
}

inline bool KCLDecryptUA(LPUSTR input, size_t len, LPKCLSK key, LPUSTR output) {
    KCLCryptArgs args = { input, len, key, output, false };
    KCLStdCall(KCL_VEH_MAGIC, FUNC_DECRYPT_UA, &args, sizeof(args));
    return args.result;
}

inline bool KCLCryptA(LPSTR input, size_t len, LPKCLSK key, LPSTR output) {
    KCLCryptArgs args = { input, len, key, output, false };
    KCLStdCall(KCL_VEH_MAGIC, FUNC_CRYPT_A, &args, sizeof(args));
    return args.result;
}

inline bool KCLDecryptA(LPSTR input, size_t len, LPKCLSK key, LPSTR output) {
    KCLCryptArgs args = { input, len, key, output, false };
    KCLStdCall(KCL_VEH_MAGIC, FUNC_DECRYPT_A, &args, sizeof(args));
    return args.result;
}

inline bool KCLCryptW(LPWSTR input, size_t len, LPKCLSK key, LPWSTR output) {
    KCLCryptArgs args = { input, len, key, output, false };
    KCLStdCall(KCL_VEH_MAGIC, FUNC_CRYPT_W, &args, sizeof(args));
    return args.result;
}

inline bool KCLDecryptW(LPWSTR input, size_t len, LPKCLSK key, LPWSTR output) {
    KCLCryptArgs args = { input, len, key, output, false };
    KCLStdCall(KCL_VEH_MAGIC, FUNC_DECRYPT_W, &args, sizeof(args));
    return args.result;
}

#endif