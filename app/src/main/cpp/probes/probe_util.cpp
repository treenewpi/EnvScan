#include "probe_util.h"
#include <cstdlib>
#include <cstring>

uint64_t elf_byte_sum(const uint8_t* p, size_t n) {
    uint64_t s = 0;
    if (!p) return 0;
    for (size_t i = 0; i < n; i++) s += p[i];
    return s;
}

int maps_precheck_addr(uint64_t addr, const MapsVma* vmas, int n) {
    if (!vmas || n <= 0) return 1;
    for (int i = 0; i < n; i++) {
        if (addr >= vmas[i].start && addr < vmas[i].end) {
            return strchr(vmas[i].perms, 'r') ? 0 : 2;
        }
    }
    return 1;
}

bool prop_serial_abnormal(uint32_t serial, const char* value) {
    size_t n = value ? strlen(value) : 0;
    uint32_t slen = serial >> 24;
    if (slen != n) return true;
    if (n == 0 && serial != 0 && (serial & 0x00FFFFFFu) != 0) return true;
    // Dirty bit stuck on a fully-readable value is a resetprop leftover.
    if ((serial & 1u) && n > 0 && slen == n) return true;
    return false;
}

static uint32_t pa_u32(const uint8_t* p) {
    uint32_t v = 0;
    memcpy(&v, p, 4);
    return v;
}

static size_t pa_bt_size(uint32_t namelen) {
    return (20u + namelen + 1u + 3u) & ~3u;
}

static int pa_cmp_name(const uint8_t* node, uint32_t namelen, const char* comp, uint32_t clen) {
    if (namelen < clen) return -1;
    if (namelen > clen) return 1;
    return memcmp(node + 20, comp, clen);
}

static const uint8_t* pa_data(const uint8_t* p) { return p + 128; }

static int pa_walk_node(const uint8_t* data, uint32_t used, uint32_t off, int depth, int is_root,
                        uint8_t* seen, PropAreaWalk* out) {
    if (depth > 48) {
        out->hole = 1;
        return 0;
    }
    if (!is_root && off == 0) return 1;
    if (off >= used || off + 20 > used) {
        out->hole = 1;
        return 0;
    }
    if (seen[off]) return 1;
    seen[off] = 1;
    const uint8_t* n = data + off;
    uint32_t namelen = pa_u32(n + 0);
    uint32_t prop = pa_u32(n + 4);
    uint32_t left = pa_u32(n + 8);
    uint32_t right = pa_u32(n + 12);
    uint32_t children = pa_u32(n + 16);
    if (namelen > 256) {
        out->hole = 1;
        return 0;
    }
    size_t nsz = pa_bt_size(namelen);
    if (off + nsz > used) {
        out->hole = 1;
        return 0;
    }
    if (prop) {
        if (prop + 96 > used) {
            out->hole = 1;
        } else {
            out->active++;
            seen[prop] = 1;
        }
    }
    if (left && !pa_walk_node(data, used, left, depth + 1, 0, seen, out)) return 0;
    if (right && !pa_walk_node(data, used, right, depth + 1, 0, seen, out)) return 0;
    if (children && !pa_walk_node(data, used, children, depth + 1, 0, seen, out)) return 0;
    return 1;
}

int walk_prop_area(const uint8_t* p, size_t n, PropAreaWalk* out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    if (!p || n < 128) return 0;
    uint32_t bytes_used = pa_u32(p + 0);
    uint32_t serial = pa_u32(p + 4);
    uint32_t magic = pa_u32(p + 8);
    out->magic = magic;
    out->area_serial = serial;
    out->bytes_used = bytes_used;
    if (magic != kPropAreaMagic) return 0;
    out->valid = 1;
    size_t dlen = n - 128;
    if (bytes_used == 0) return 1;
    if (bytes_used > dlen) {
        out->hole = 1;
        bytes_used = (uint32_t)dlen;
        out->bytes_used = bytes_used;
    }
    if (bytes_used < 20) {
        out->hole = 1;
        return 1;
    }
    // Cap walk to 1MiB so a corrupt area cannot explode.
    if (bytes_used > (1u << 20)) bytes_used = 1u << 20;
    uint8_t* seen = (uint8_t*)malloc(bytes_used);
    if (!seen) return 1;
    memset(seen, 0, bytes_used);
    pa_walk_node(p + 128, bytes_used, 0, 0, 1, seen, out);

    // Leftover prop_info names that the trie never visited.
    static const char* watch[] = {"ro.boot.flash.locked", "ro.boot.vbmeta.device_state",
                                  "ro.boot.verifiedbootstate", nullptr};
    const uint8_t* data = p + 128;
    for (int k = 0; watch[k]; k++) {
        size_t klen = strlen(watch[k]);
        int hits = 0;
        for (uint32_t i = 0; i + klen < bytes_used; i++) {
            if (memcmp(data + i, watch[k], klen) == 0 && data[i + klen] == 0) hits++;
        }
        // Trie stores path components, not the dotted name. One full-name
        // C-string is the prop_info; two or more is a resetprop leftover.
        if (hits >= 2) out->remains = 1;
    }
    free(seen);
    return 1;
}

static const uint8_t* pa_find_bt(const uint8_t* data, uint32_t used, uint32_t off, const char* comp,
                                 uint32_t clen, int depth) {
    if (depth > 48 || off == 0 || off + 20 > used) return nullptr;
    while (off && off + 20 <= used) {
        const uint8_t* n = data + off;
        uint32_t namelen = pa_u32(n + 0);
        if (namelen > 256) return nullptr;
        int c = pa_cmp_name(n, namelen, comp, clen);
        if (c == 0) return n;
        uint32_t next = c < 0 ? pa_u32(n + 8) : pa_u32(n + 12);
        if (!next || next == off) return nullptr;
        off = next;
        if (++depth > 48) return nullptr;
    }
    return nullptr;
}

int prop_area_lookup(const uint8_t* p, size_t n, const char* key, uint32_t* serial, char* val, size_t valn) {
    if (!p || n < 128 || !key || !*key) return 0;
    if (pa_u32(p + 8) != kPropAreaMagic) return 0;
    uint32_t used = pa_u32(p + 0);
    size_t dlen = n - 128;
    if (used > dlen) used = (uint32_t)dlen;
    if (used < 20) return 0;
    const uint8_t* data = p + 128;
    const uint8_t* cur = data;  // root
    const char* remain = key;
    for (;;) {
        const char* sep = strchr(remain, '.');
        uint32_t clen = sep ? (uint32_t)(sep - remain) : (uint32_t)strlen(remain);
        uint32_t children = pa_u32(cur + 16);
        const uint8_t* node = pa_find_bt(data, used, children, remain, clen, 0);
        if (!node) return 0;
        if (!sep) {
            uint32_t prop = pa_u32(node + 4);
            if (!prop || prop + 96 > used) return 0;
            if (serial) *serial = pa_u32(data + prop);
            if (val && valn) {
                size_t cpy = 91;
                if (cpy > valn - 1) cpy = valn - 1;
                memcpy(val, data + prop + 4, cpy);
                val[cpy] = 0;
                // trim at first NUL already guaranteed if area is well-formed
            }
            return 1;
        }
        cur = node;
        remain = sep + 1;
    }
}
