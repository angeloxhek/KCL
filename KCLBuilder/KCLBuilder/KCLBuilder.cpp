#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <string>

// Подключаем ваш обновленный заголовочный файл
#include "KCLUser.h"

// --- Вспомогательные функции ---

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
    out << "// Сгенерировано автоматически. Размер: " << data.size() << " байт\n";
    out << "std::vector<unsigned char> " << varName << " = {\n    ";

    out << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < data.size(); i++) {
        out << "0x" << std::setw(2) << (int)data[i];
        if (i != data.size() - 1) out << ", ";
        // Перенос строки каждые 16 байт для красоты
        if ((i + 1) % 16 == 0 && i != data.size() - 1) out << "\n    ";
    }
    out << "\n};\n";
    return true;
}

int main() {
    std::cout << "--- GHOST DLL BUILDER ---\n\n";

    // ==========================================
    // ЭТАП 1: Шифрование самой DLL
    // ==========================================
    std::cout << "[*] Phase 1: Encrypting KrnlCryptoLib.dll...\n";
    std::string dllFile = "KrnlCryptoLib.dll";
    std::vector<UCHAR> dllData = ReadBinaryFile(dllFile);

    if (dllData.empty()) {
        std::cout << "[!] Failed to read " << dllFile << "\n";
        return 1;
    }

    // Шифруем независимым алгоритмом (Ключ: 0x7A)
    IndependentCrypt(dllData, 0x7F);
    std::string encDllFile = "keypreset.bin";

    if (WriteBinaryFile(encDllFile, dllData)) {
        std::cout << "[+] Saved encrypted DLL to: " << encDllFile << "\n\n";
    }
    else {
        std::cout << "[!] Failed to write encrypted DLL.\n";
        return 1;
    }

    // Сохраняем результат в виде текста с C++ массивом!
    std::string arrayFile = "KCLArray.cpp";
    if (DumpToCArray(dllData, "DLLPayload", arrayFile)) {
        std::cout << "[+] Saved C++ array to: " << arrayFile << "\n";
    }
    else {
        std::cout << "[!] Failed to write C++ array.\n";
    }

    // ==========================================
    // ЭТАП 2: Подготовка ключей и шифрование Payload
    // ==========================================
    std::cout << "[*] Phase 2: Processing Target Payload...\n";

    // Загружаем оригинальную DLL для работы VEH
    HMODULE hLib = LoadLibraryA(dllFile.c_str());
    if (!hLib) {
        std::cout << "[!] Failed to load " << dllFile << " into memory for VEH processing.\n";
        return 1;
    }

    std::string targetFile = "KCLSuccess.exe";
    std::vector<UCHAR> targetData = ReadBinaryFile(targetFile);
    if (targetData.empty()) {
        std::cout << "[!] Failed to read " << targetFile << "\n";
        return 1;
    }

    // Генерируем ключи
    size_t masterSeed = 0x1337BEEF7BADF00D;
    KCLRSK rawKey = { 0 };
    KCLSK secKey = { 0 };

    if (!KCLFillRawSecKey(&rawKey, masterSeed)) return 1;

    DumpRawKey(rawKey, "rawKey.txt");

    if (!KCLGetSecKey(&rawKey, &secKey)) return 1;

    DumpSecKey(secKey, "secKey.txt");

    // Шифруем массив victory.exe через VEH-DLL
    std::cout << "[*] Encrypting " << targetFile << " via VEH...\n";
    if (!KCLCryptUA(targetData.data(), targetData.size(), &secKey, targetData.data())) {
        std::cout << "[!] Payload encryption failed.\n";
        return 1;
    }

    std::string encTargetFile = "KCLSuccess.bin";
    if (WriteBinaryFile(encTargetFile, targetData)) {
        std::cout << "[+] Saved encrypted DLL to: " << encTargetFile << "\n\n";
    }
    else {
        std::cout << "[!] Failed to write encrypted DLL.\n";
        return 1;
    }

    // Сохраняем результат в виде текста с C++ массивом!
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