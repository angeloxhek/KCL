#pragma once
#ifndef KCLMASKS
#define KCLMASKS 1
#include <math.h>
#include <limits.h>
#define MAGICMASK 0xDD248D3132AB6400
static size_t* GetKCLMagic1P() { static size_t val = GenKCLMagic(0x1B124577E712A000); return &val; }
static size_t* GetKCLMagic2P() { static size_t val = GenKCLMagic(0x11526760D6F50000); return &val; }
static size_t* GetKCLMagic3P() { static size_t val = 0xFFFFFFFFFFFFFFC5; return &val; }
static size_t* GetKCLMagic4P() { static size_t val = GenKCLMagic(0x243F6A8885A30000); return &val; }
static size_t* GetKCLMagic5P() { static size_t val = GenKCLMagic(0x517CC1B727220C00) & 0xFF; return &val; }
static size_t* GetKCLMagic6P() { static size_t val = GenKCLMagic(0x50ABF038FF00000); return &val; }
static size_t GetKCLMagic1() { size_t* val = GetKCLMagic1P(); return *val; }
static size_t GetKCLMagic2() { size_t* val = GetKCLMagic2P(); return *val; }
static size_t GetKCLMagic3() { size_t* val = GetKCLMagic3P(); return *val; }
static size_t GetKCLMagic4() { size_t* val = GetKCLMagic4P(); return *val; }
static size_t GetKCLMagic5() { size_t* val = GetKCLMagic5P(); return *val; }
static size_t GetKCLMagic6() { size_t* val = GetKCLMagic6P(); return *val; }
#define GETSECKEYMIX(h) (h ^= h >> 33, h *= 0xff51afd7ed558ccd, h ^= h >> 33, h *= 0xc4ceb9fe1a85ec53, h ^= h >> 33)
#endif