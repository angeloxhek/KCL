# 🔐 KCL (Kernel Crypto Library) - Advanced Execution PoC

[🇺🇸 English](#en--english) | [🇷🇺 Русский](#ru--русский)

<div align="center">
  <img src="https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white" />
  <img src="https://img.shields.io/badge/Malware_Analysis-8C1515?style=for-the-badge" />
  <img src="https://img.shields.io/badge/CTF_Hub-black?style=for-the-badge" />
</div>

<br/>

## EN / English

**Welcome to the KCL Hub.** 

This `main` branch contains the pure, open-source architectural blueprint of an advanced Malware/Crypter ecosystem. It is an interactive Proof-of-Concept demonstrating hardcore low-level Windows techniques. You can study the code, compile it, and see how it works under the hood.

**Techniques implemented in this architecture:**
* **Reflective DLL Injection** (In-memory loading without touching the disk).
* **Process Hollowing / RunPE** (Executing the final payload entirely in memory).
* **VEH API Routing** (Using Vectored Exception Handling to obfuscate cryptographic function calls).
* **NTFS ADS Hiding** (Using Alternate Data Streams for stealthy deployment).
* **Anti-Debugging** (PEB, NtGlobalFlag, RDTSC timing checks).
* **Environment Keying** (Payload decryption depends on parent-process environment variables).

### The CTF Challenges
While this branch is for educational and portfolio purposes, KCL is also a game. I have prepared specialized challenges in separate branches. Use the knowledge you gained from reading the source code here to beat the black-box tasks there!

Choose your destiny:

* [ SOON ]

*(Did you beat a challenge? Send your write-up to my DM!)*

<br/>

> *Love and kisses to everyone! I hope you enjoy my projects.* 🤍

---

## RU / Русский

**Добро пожаловать в хаб KCL.**

В этой ветке (`main`) находится чистый, полностью открытый исходный код архитектуры продвинутой экосистемы малвари/крипторов. Это Proof-of-Concept, демонстрирующий хардкорные низкоуровневые техники Windows. Вы можете изучать код, компилировать его и смотреть, как магия работает изнутри.

**Техники, реализованные в архитектуре:**
* **Reflective DLL Injection** (Загрузка библиотеки в память без касания диска).
* **Process Hollowing / RunPE** (Запуск финального пейлоада исключительно в оперативной памяти).
* **VEH API Routing** (Использование Vectored Exception Handling для скрытия вызовов крипто-функций).
* **NTFS ADS Hiding** (Использование альтернативных потоков данных NTFS для скрытия файлов).
* **Anti-Debugging** (Проверки PEB, NtGlobalFlag, замеры таймингов через RDTSC).
* **Environment Keying** (Зависимость расшифровки от переменных среды).

### 🎮 CTF Задания (Челленджи)
Хотя эта ветка создана как портфолио и в образовательных целях, KCL — это еще и игра. В других ветках репозитория я подготовил специальные задания. Используйте знания архитектуры, полученные здесь, чтобы взломать Black-box бинарники там!

Выберите свое испытание:

* [ СКОРО ]

*(Смогли пройти уровень? Присылайте решение мне в ЛС!)*

<br/>

> *Всех люблю, всех целую! Надеюсь, вам понравятся мои проекты.* 🤍
