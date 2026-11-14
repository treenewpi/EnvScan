#pragma once
#include <cstdint>
#include <cstddef>

// SIMD TBL+UADDW is a plain byte-sum of executable bytes.
uint64_t elf_byte_sum(const uint8_t* p, size_t n);

// Android prop serial: high 8 bits = value length. resetprop often leaves
// serial length != strlen(value) ("Abnormal prop serial for: ...").
bool prop_serial_abnormal(uint32_t serial, const char* value);

// AOSP bionic prop_area: magic 'PROP', version 0xfc6ed0ab, 128-byte header.
static constexpr uint32_t kPropAreaMagic = 0x504f5250u;
static constexpr uint32_t kPropAreaVersion = 0xfc6ed0abu;

struct PropAreaWalk {
    int valid = 0;
    int hole = 0;
    int remains = 0;
    int active = 0;
    uint32_t bytes_used = 0;
    uint32_t magic = 0;
    uint32_t area_serial = 0;
};

// Walk a mapped /dev/__properties__ context file. Host-testable.
int walk_prop_area(const uint8_t* p, size_t n, PropAreaWalk* out);

// Look up key in a mapped prop_area. Returns 1 if found.
int prop_area_lookup(const uint8_t* p, size_t n, const char* key, uint32_t* serial, char* val, size_t valn);

// maps pre-check against a synthetic VMA table.
// 0 = readable, 1 = range not fully mapped, 2 = non-readable range.
struct MapsVma {
    uint64_t start = 0;
    uint64_t end = 0;
    char perms[8] = {};
};
int maps_precheck_addr(uint64_t addr, const MapsVma* vmas, int n);
