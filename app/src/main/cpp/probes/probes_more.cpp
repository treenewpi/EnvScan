#include "probes.h"
#include "probe_util.h"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <linux/elf.h>
#include <signal.h>
#include <sys/auxv.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/system_properties.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <vector>
#include <sys/uio.h>

#ifndef NT_ARM_HW_BREAK
#define NT_ARM_HW_BREAK 0x400
#endif
#ifndef NT_ARM_HW_WATCH
#define NT_ARM_HW_WATCH 0x401
#endif
#ifndef PR_GET_SECCOMP
#define PR_GET_SECCOMP 21
#endif
#ifndef PR_GET_NO_NEW_PRIVS
#define PR_GET_NO_NEW_PRIVS 39
#endif
#ifndef SYS_prctl
#define SYS_prctl 167
#endif
#ifndef SYS_uname
#define SYS_uname 160
#endif
#ifndef SYS_getuid
#define SYS_getuid 174
#endif
#ifndef SYS_getpid
#define SYS_getpid 172
#endif
#ifndef SYS_openat
#define SYS_openat 56
#endif
#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif
#ifndef SYSLOG_ACTION_READ_ALL
#define SYSLOG_ACTION_READ_ALL 3
#endif
#ifndef SYSLOG_ACTION_SIZE_BUFFER
#define SYSLOG_ACTION_SIZE_BUFFER 10
#endif
#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 1u
#endif
#ifndef __NR_memfd_create
#define __NR_memfd_create 279
#endif
#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_DETACH
#define PTRACE_DETACH 17
#endif

static bool exists_path(const char* p) {
    return path_visible(p);
}

static std::string read_file(const char* path, size_t maxn = 1 << 20) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return {};
    std::string s;
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        s.append(buf, (size_t)n);
        if (s.size() >= maxn) break;
    }
    close(fd);
    return s;
}

static std::string prop(const char* k) {
    char v[PROP_VALUE_MAX] = {};
    __system_property_get(k, v);
    return v;
}

struct MapEnt {
    unsigned long start = 0, end = 0, offset = 0, inode = 0;
    char perms[8] = {};
    unsigned devmaj = 0, devmin = 0;
    std::string path;
};

static std::vector<MapEnt> parse_maps() {
    std::vector<MapEnt> out;
    auto maps = read_file("/proc/self/maps");
    const char* sp = maps.c_str();
    while (*sp) {
        const char* nl = strchr(sp, '\n');
        size_t n = nl ? (size_t)(nl - sp) : strlen(sp);
        std::string line(sp, n);
        MapEnt e;
        char path[512] = {};
        if (sscanf(line.c_str(), "%lx-%lx %7s %lx %x:%x %lu %511[^\n]",
                   &e.start, &e.end, e.perms, &e.offset, &e.devmaj, &e.devmin, &e.inode, path) >= 5) {
            if (path[0] == ' ') {
                char* p = path;
                while (*p == ' ') p++;
                e.path = p;
            } else {
                e.path = path;
            }
            out.push_back(e);
        }
        if (!nl) break;
        sp = nl + 1;
    }
    return out;
}

static const MapEnt* vma_at(const std::vector<MapEnt>& maps, unsigned long addr) {
    for (auto& e : maps) {
        if (addr >= e.start && addr < e.end) return &e;
    }
    return nullptr;
}

static int maps_precheck_status(const std::vector<MapEnt>& maps, unsigned long addr) {
    MapsVma buf[8];
    int n = 0;
    for (auto& e : maps) {
        if (addr < e.start || addr >= e.end) continue;
        if (n < 8) {
            buf[n].start = e.start;
            buf[n].end = e.end;
            memcpy(buf[n].perms, e.perms, sizeof(buf[n].perms));
            n++;
        }
    }
    return maps_precheck_addr(addr, buf, n);
}

static void maps_precheck_hit(int st, unsigned long addr, const std::string& path, int* issues,
                              std::string* detail) {
    if (st == 0) return;
    (*issues)++;
    char line[280];
    if (st == 2) {
        snprintf(line, sizeof(line),
                 "maps pre-check: non-readable range for addr %lu\ncheck [%s] error\n", addr, path.c_str());
    } else {
        snprintf(line, sizeof(line),
                 "maps pre-check: range not fully mapped for addr %lu\ncheck [%s] error\n", addr, path.c_str());
    }
    *detail += line;
}

static bool ptr_readable(const std::vector<MapEnt>& maps, const void* p, size_t n = sizeof(void*)) {
    if (!p) return false;
    unsigned long a = (unsigned long)p;
    if (a < 4096ul) return false;
    const MapEnt* v = vma_at(maps, a);
    if (!v || !strchr(v->perms, 'r')) return false;
    if (n && a + n > v->end) return false;
    return true;
}

static bool stock_xom_path(const std::string& path) {
    return path.find("/system/") == 0 || path.find("/apex/") == 0 || path.find("/vendor/") == 0 ||
           path.find("/product/") == 0;
}

static uint32_t crc32_ieee(const uint8_t* data, size_t len) {
    uint32_t c = 0xffffffffu;
    for (size_t i = 0; i < len; i++) {
        c ^= data[i];
        for (int b = 0; b < 8; b++) c = (c >> 1) ^ (0xedb88320u & -(c & 1u));
    }
    return ~c;
}

// detect_elf_checksum: TBL+UADDW over in-memory bytes is a plain sum.
static int elf_sdk_level() {
    char sdk[PROP_VALUE_MAX] = {}, preview[PROP_VALUE_MAX] = {};
    __system_property_get("ro.build.version.sdk", sdk);
    __system_property_get("ro.build.version.preview_sdk", preview);
    return atoi(sdk) + atoi(preview);
}

struct ElfXSeg {
    uint64_t vaddr = 0, filesz = 0, offset = 0, expected = 0;
};

static bool elf_fetch_xsegs(const char* path, std::vector<ElfXSeg>* out, std::string* err) {
    int fd = (int)svc5(SYS_openat, AT_FDCWD, (long)path, O_RDONLY | O_CLOEXEC, 0, 0);
    if (fd < 0) fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        *err = "fetch_checksum_of_library open file error ";
        *err += path;
        return false;
    }
    struct stat st {};
    if (fstat(fd, &st) || st.st_size < (off_t)sizeof(Elf64_Ehdr)) {
        close(fd);
        *err = "fetch_checksum_of_library invalid elf header";
        return false;
    }
    size_t sz = (size_t)st.st_size;
    void* mm = mmap(nullptr, sz, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mm == MAP_FAILED) {
        *err = "allocate elf executable section error ";
        *err += path;
        return false;
    }
    auto* eh = (Elf64_Ehdr*)mm;
    if (eh->e_ident[0] != 0x7f || eh->e_ident[1] != 'E' || eh->e_ident[2] != 'L' || eh->e_ident[3] != 'F' ||
        eh->e_ident[EI_CLASS] != ELFCLASS64 || eh->e_phentsize != sizeof(Elf64_Phdr)) {
        munmap(mm, sz);
        *err = "fetch_checksum_of_library invalid elf header";
        return false;
    }
    auto* ph = (Elf64_Phdr*)((uint8_t*)mm + eh->e_phoff);
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD || !(ph[i].p_flags & PF_X)) continue;
        if (ph[i].p_offset + ph[i].p_filesz > sz) continue;
        ElfXSeg s;
        s.vaddr = ph[i].p_vaddr;
        s.filesz = ph[i].p_filesz;
        s.offset = ph[i].p_offset;
        s.expected = elf_byte_sum((uint8_t*)mm + ph[i].p_offset, (size_t)ph[i].p_filesz);
        out->push_back(s);
    }
    munmap(mm, sz);
    if (out->empty()) {
        *err = "detect_elf_checksum execSection == null";
        return false;
    }
    return true;
}

static bool map_files_any_ok(const std::vector<MapEnt>& maps) {
    int ok = 0;
    for (auto& e : maps) {
        if (!e.inode || e.path.empty() || e.path[0] != '/') continue;
        char mf[96];
        snprintf(mf, sizeof(mf), "/proc/self/map_files/%lx-%lx", e.start, e.end);
        if (faccessat(AT_FDCWD, mf, F_OK, 0) == 0) {
            ok++;
            if (ok >= 2) return true;
        }
    }
    return ok > 0;
}

static bool phdr_has_path(const char* needle) {
    struct Cookie {
        const char* n;
        bool hit;
    } c{needle, false};
    dl_iterate_phdr(
            [](struct dl_phdr_info* info, size_t, void* data) -> int {
                auto* ck = (Cookie*)data;
                if (info->dlpi_name && strstr(info->dlpi_name, ck->n)) {
                    ck->hit = true;
                    return 1;
                }
                return 0;
            },
            &c);
    return c.hit;
}

static void crc_target_map_files(const std::vector<MapEnt>& maps, const std::string& path, bool mf_ok,
                                 int* issues, std::string* detail) {
    if (!mf_ok) return;
    for (auto& e : maps) {
        if (e.path != path || !e.inode) continue;
        char mf[96];
        snprintf(mf, sizeof(mf), "/proc/self/map_files/%lx-%lx", e.start, e.end);
        int fd = open(mf, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            (*issues)++;
            *detail += "File-backed probe memory exists in /proc/self/maps but missing in /proc/self/map_files.\n";
            *detail += "check [";
            *detail += path;
            *detail += "] find hook\n";
            return;
        }
        struct stat st {};
        fstat(fd, &st);
        char link[512] = {};
        ssize_t ln = readlink(mf, link, sizeof(link) - 1);
        close(fd);
        if (e.inode && (unsigned long)st.st_ino != e.inode) {
            (*issues)++;
            char line[240];
            snprintf(line, sizeof(line), "Found inconsistent inode : %lu orig inode ->  : %lu\ncheck [%s] find hook\n",
                     (unsigned long)st.st_ino, e.inode, path.c_str());
            *detail += line;
            return;
        }
        if (ln > 0) {
            link[ln] = 0;
            if (strstr(link, "(deleted)") || strstr(link, "/data/adb/") || strstr(link, "magisk") ||
                strstr(link, "zygisk")) {
                (*issues)++;
                *detail += "find hook file ";
                *detail += link;
                *detail += "\ncheck [";
                *detail += path;
                *detail += "] find hook\n";
                return;
            }
        }
    }
}

static void crc_pt_load_range(const std::vector<MapEnt>& maps, const std::string& path,
                              const std::vector<ElfXSeg>& segs, int* issues, std::string* detail) {
    long ps = sysconf(_SC_PAGESIZE);
    if (ps < 4096) ps = 4096;
    auto align = [&](uint64_t v) { return (v + (uint64_t)ps - 1) & ~((uint64_t)ps - 1); };
    for (auto& e : maps) {
        if (e.path != path || e.perms[2] != 'x') continue;
        bool cover = false;
        for (auto& s : segs) {
            uint64_t poff = s.offset;
            uint64_t pend = poff + align(s.filesz);
            uint64_t voff = e.offset;
            uint64_t vend = voff + (e.end - e.start);
            if (voff < pend && vend > poff) {
                cover = true;
                break;
            }
            // offset-0 r-x often includes ELF header before p_offset.
            if (e.offset == 0 && s.offset < (uint64_t)(e.end - e.start)) {
                cover = true;
                break;
            }
        }
        if (!cover) {
            (*issues)++;
            char line[220];
            snprintf(line, sizeof(line),
                     "executable mapping is outside declared executable PT_LOAD offset=0x%lx\n"
                     "check [%s] find hook\n",
                     e.offset, path.c_str());
            *detail += line;
            return;
        }
    }
}

static void crc_checkfile_uid(const std::string& path, const std::vector<MapEnt>& maps, int* issues,
                              std::string* detail) {
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    struct stat st {};
    fstat(fd, &st);
    char lpath[64];
    snprintf(lpath, sizeof(lpath), "/proc/self/fd/%d", fd);
    char got[512] = {};
    ssize_t ln = readlink(lpath, got, sizeof(got) - 1);
    uid_t ouid = st.st_uid, ogid = st.st_gid;
    close(fd);
    if (ln > 0) {
        got[ln] = 0;
        if (strstr(got, "(deleted)") || strstr(got, "/data/adb/") || strstr(got, "magisk")) {
            (*issues)++;
            *detail += "checkFileIsLegal path validation failed [";
            *detail += got;
            *detail += "]\ncheck [";
            *detail += path;
            *detail += "] find hook\n";
            return;
        }
    }
    uid_t me = getuid();
    if (me >= 10000 && st.st_uid == me) {
        (*issues)++;
        char line[200];
        snprintf(line, sizeof(line), "checkFileIsLegal uid&gid validation failed uid=%u gid=%u me=%u\ncheck [%s] find hook\n",
                 (unsigned)st.st_uid, (unsigned)st.st_gid, (unsigned)me, path.c_str());
        *detail += line;
        return;
    }
    for (auto& e : maps) {
        if (e.path != path || !e.inode) continue;
        char mf[96];
        snprintf(mf, sizeof(mf), "/proc/self/map_files/%lx-%lx", e.start, e.end);
        int mfd = open(mf, O_RDONLY | O_CLOEXEC);
        if (mfd < 0) break;
        struct stat ms {};
        fstat(mfd, &ms);
        close(mfd);
        if (ms.st_uid != ouid || ms.st_gid != ogid) {
            (*issues)++;
            char line[220];
            snprintf(line, sizeof(line),
                     "checkFileIsLegal uid&gid validation failed map %u:%u file %u:%u\ncheck [%s] find hook\n",
                     (unsigned)ms.st_uid, (unsigned)ms.st_gid, (unsigned)ouid, (unsigned)ogid, path.c_str());
            *detail += line;
            return;
        }
        break;
    }
}

static void crc_self_mapping(int* issues, std::string* detail) {
    Dl_info di {};
    if (!dladdr((const void*)&probe_elf_crc, &di) || !di.dli_fname) return;
    std::string fname = di.dli_fname;
    // Use this library's own soname so the technique stays valid in any host.
    std::string base = fname;
    size_t slash = base.rfind('/');
    if (slash != std::string::npos) base = base.substr(slash + 1);
    bool deleted = fname.find("(deleted)") != std::string::npos;
    if (base.empty() || deleted) {
        (*issues)++;
        *detail += "invalidOrDeletedSelfMappingPath=true self=" + base + " path=";
        *detail += fname;
        *detail += "\ncheck [";
        *detail += fname;
        *detail += "] find hook\n";
    }
    if (!deleted && !base.empty() && !phdr_has_path(base.c_str())) {
        (*issues)++;
        *detail += "dl_iterate_phdr registration missing=true self=" + base + "\n";
        *detail += "check [" + base + "] find hook\n";
    }
}

static bool load_elf_text(const char* path, std::vector<uint8_t>* text, uint64_t* vaddr_out) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    off_t sz = lseek(fd, 0, SEEK_END);
    if (sz < (off_t)sizeof(Elf64_Ehdr)) {
        close(fd);
        return false;
    }
    lseek(fd, 0, SEEK_SET);
    std::vector<uint8_t> file((size_t)sz);
    if (read(fd, file.data(), (size_t)sz) != sz) {
        close(fd);
        return false;
    }
    close(fd);
    if (file[0] != 0x7f || file[1] != 'E' || file[2] != 'L' || file[3] != 'F') return false;
    auto* eh = (Elf64_Ehdr*)file.data();
    if (eh->e_ident[EI_CLASS] != ELFCLASS64) return false;
    auto* ph = (Elf64_Phdr*)(file.data() + eh->e_phoff);
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD && (ph[i].p_flags & PF_X)) {
            if (ph[i].p_offset + ph[i].p_filesz > file.size()) continue;
            size_t n = (size_t)ph[i].p_filesz;
            if (n > 1 << 20) n = 1 << 20;
            text->assign(file.data() + ph[i].p_offset, file.data() + ph[i].p_offset + n);
            if (vaddr_out) *vaddr_out = ph[i].p_vaddr;
            return !text->empty();
        }
    }
    return false;
}

std::string elf_text_crc(const char* path) {
    std::vector<uint8_t> text;
    uint64_t va = 0;
    if (!load_elf_text(path, &text, &va) || text.empty()) return "unreadable";
    char buf[16];
    snprintf(buf, sizeof(buf), "%08x", crc32_ieee(text.data(), text.size()));
    return buf;
}

static std::string module_path_from_maps(const char* needle) {
    for (auto& e : parse_maps()) {
        if (e.path.find(needle) != std::string::npos && strchr(e.perms, 'x')) return e.path;
    }
    return {};
}

static unsigned long module_base_from_maps(const char* needle) {
    for (auto& e : parse_maps()) {
        if (e.path.find(needle) != std::string::npos && strchr(e.perms, 'x')) return e.start;
    }
    return 0;
}

static Probe run_crc_check() {
    Probe p;
    auto maps = parse_maps();
    std::string detail;
    int issues = 0, checked = 0;
    int sdk = elf_sdk_level();
    // sdk+preview_sdk > 29 → apex paths, else /system.
    std::vector<std::string> targets;
    if (sdk > 29) {
        targets.emplace_back("/apex/com.android.runtime/lib64/bionic/libc.so");
        targets.emplace_back("/apex/com.android.runtime/bin/linker64");
    } else {
        targets.emplace_back("/system/lib64/libc.so");
        targets.emplace_back("/system/bin/linker64");
    }
    std::string art;
    for (auto& e : maps) {
        if (e.path.find("/libart.so") != std::string::npos && e.path[0] == '/') {
            art = e.path;
            break;
        }
    }
    if (!art.empty()) targets.push_back(art);

    for (auto& path : targets) {
        checked++;
        std::vector<ElfXSeg> segs;
        std::string ferr;
        if (!elf_fetch_xsegs(path.c_str(), &segs, &ferr)) {
            issues++;
            detail += ferr;
            detail += "\ncheck [";
            detail += path;
            detail += "] find hook\n";
            continue;
        }
        unsigned long bias = 0;
        bool bias_ok = false;
        bool seen_maps = false;
        bool rwx = false;
        for (auto& e : maps) {
            if (e.path != path) continue;
            seen_maps = true;
            if (e.offset == 0) {
                bias = e.start;
                bias_ok = true;
            } else if (!bias_ok) {
                bias = e.start - e.offset;
                bias_ok = true;
            }
            // Permission triad only: rwxp is an inline-hook trampoline.
            // strchr('w') on "r-xp" is false; do not treat page-rounded r-x as rwx.
            if (e.perms[0] == 'r' && e.perms[1] == 'w' && e.perms[2] == 'x') rwx = true;
        }
        if (!seen_maps) {
            detail += "detect_elf_checksum find in map not find ";
            detail += path;
            detail += "\n";
            continue;
        }
        if (rwx) {
            issues++;
            detail += "check [";
            detail += path;
            detail += "] find hook rwx\n";
            continue;
        }
        bool lib_issue = false;
        // checkFileIsLegal: maps inode/dev vs stat(path). Overlay/bind
        // makes map get != file inode → find hook.
        struct stat st {};
        if (stat(path.c_str(), &st) == 0) {
            for (auto& e : maps) {
                if (e.path != path || !e.inode) continue;
                unsigned long st_maj = major(st.st_dev), st_min = minor(st.st_dev);
                // Device maj:min encoding in maps is hex and often disagrees
                // with major(st_dev); checkFileIsLegal compares the inode.
                if (e.inode != (unsigned long)st.st_ino) {
                    issues++;
                    char line[240];
                    snprintf(line, sizeof(line),
                             "checkFileIsLegal inode validation failed ,map get %u:%u ino=%lu file %lu:%lu ino=%lu\n"
                             "check [%s] find hook\n",
                             e.devmaj, e.devmin, e.inode, st_maj, st_min, (unsigned long)st.st_ino, path.c_str());
                    detail += line;
                    lib_issue = true;
                    break;
                }
            }
            if (lib_issue) continue;
        }
        if (!bias_ok) {
            detail += path;
            detail += " maps bias unavailable\n";
            continue;
        }
        size_t compared = 0;
        for (auto& s : segs) {
            unsigned long addr = (unsigned long)(bias + s.vaddr);
            size_t left = (size_t)s.filesz;
            uint64_t mem_sum = 0;
            size_t hashed = 0;
            size_t skipped_x = 0;
            bool unread_x = false;
            while (left) {
                const MapEnt* v = vma_at(maps, addr);
                if (!v) {
                    lib_issue = true;
                    maps_precheck_hit(1, addr, path, &issues, &detail);
                    break;
                }
                size_t chunk = (size_t)(v->end - addr);
                if (chunk > left) chunk = left;
                if (v->perms[0] == 'r' && v->perms[1] == 'w' && v->perms[2] == 'x') {
                    lib_issue = true;
                    issues++;
                    detail += "check [";
                    detail += path;
                    detail += "] find hook rwx\n";
                    break;
                }
                if (!strchr(v->perms, 'r')) {
                    // A10+ XOM --xp: cannot hash, not a hook by itself.
                    unread_x = true;
                    skipped_x += chunk;
                    addr += chunk;
                    left -= chunk;
                    continue;
                }
                mem_sum += elf_byte_sum((const uint8_t*)addr, chunk);
                hashed += chunk;
                compared += chunk;
                addr += chunk;
                left -= chunk;
            }
            if (lib_issue) break;
            if (hashed == 0 || skipped_x > 0) {
                if (unread_x) {
                    detail += "checksum inconclusive: execute-only mapping [";
                    detail += path;
                    detail += "] skipped=";
                    detail += std::to_string(skipped_x);
                    detail += "\n";
                }
                continue;
            }
            if (mem_sum != s.expected) {
                lib_issue = true;
                issues++;
                char line[280];
                snprintf(line, sizeof(line),
                         "check [%s] find hook bytesum=%llx expected=%llx comparedExecutableBytes=%zu\n",
                         path.c_str(), (unsigned long long)mem_sum, (unsigned long long)s.expected, hashed);
                detail += line;
                break;
            }
            // Exclusive filesz end: unmapped is a normal ELF VMA end (16K page pad
            // keeps xend inside r-x). Mapped without 'r' is
            // "non-readable range" (15673 libart maps_end → next PROT_NONE).
            unsigned long xend = (unsigned long)(bias + s.vaddr + s.filesz);
            int xst = maps_precheck_status(maps, xend);
            // Android 16 / 16K page: filesz end lands on the next PROT_NONE page.
            // That is a normal page pad, not an inline hook; keep it as a note.
            if (xst == 2) {
                detail += path + " xend non-readable (page pad)\n";
            }
            const MapEnt* tail = vma_at(maps, hashed ? (xend - 1) : (unsigned long)(bias + s.vaddr));
            // libart addr is exclusive maps_end, not filesz end.
            if (tail) {
                int mst = maps_precheck_status(maps, tail->end);
                if (mst == 2) {
                    detail += path + " maps_end non-readable (page pad)\n";
                }
            }
            if (tail && strchr(tail->perms, 'r') && tail->end > xend) {
                size_t extra_n = (size_t)(tail->end - xend);
                uint64_t extra = elf_byte_sum((const uint8_t*)xend, extra_n);
                char line[280];
                snprintf(line, sizeof(line),
                         "%s r-x tail extra=%llx n=%zu filesz=%llx maps_end=%lx (page pad)\n",
                         path.c_str(), (unsigned long long)extra, extra_n, (unsigned long long)s.filesz,
                         tail->end);
                detail += line;
            }
            char line[220];
            snprintf(line, sizeof(line),
                     "%s bytesum=%llx expected=%llx comparedExecutableBytes=%zu match\n", path.c_str(),
                     (unsigned long long)mem_sum, (unsigned long long)s.expected, hashed);
            detail += line;
        }
        if (path.find("libc.so") != std::string::npos) {
            static const char* fns[] = {"open", "openat", "faccessat", "execve", "prctl", "uname", "ptrace",
                                        nullptr};
            for (int fi = 0; fns[fi]; fi++) {
                void* f = dlsym(RTLD_DEFAULT, fns[fi]);
                if (!f) continue;
                const MapEnt* v = vma_at(maps, (unsigned long)f);
                if (!v || !strchr(v->perms, 'r')) continue;
                uint32_t w0 = 0, w1 = 0;
                memcpy(&w0, f, 4);
                memcpy(&w1, (char*)f + 4, 4);
                if (w1 == 0xD61F0200u && (w0 & 0xFF00001Fu) == 0x58000010u) {
                    issues++;
                    detail += "check [";
                    detail += path;
                    detail += "] find hook ";
                    detail += fns[fi];
                    detail += " trampoline\n";
                }
            }
        }
        // "runtime executable bytes differ from backing file offset=0x"
        // Compare each r-x VMA to the file at the maps offset (includes page tail).
        if (!lib_issue) {
            int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
            if (fd >= 0) {
                for (auto& e : maps) {
                    if (e.path != path || e.perms[2] != 'x' || !strchr(e.perms, 'r')) continue;
                    size_t n = (size_t)(e.end - e.start);
                    if (n == 0 || n > (8u << 20)) continue;
                    std::vector<uint8_t> fbuf(n);
                    ssize_t got = pread(fd, fbuf.data(), n, (off_t)e.offset);
                    if (got <= 0) continue;
                    uint64_t fsum = elf_byte_sum(fbuf.data(), (size_t)got);
                    uint64_t msum = elf_byte_sum((const uint8_t*)e.start, (size_t)got);
                    if (fsum != msum) {
                        issues++;
                        char line[280];
                        snprintf(line, sizeof(line),
                                 "runtime executable bytes differ from backing file offset=0x%lx [%s]\n"
                                 "check [%s] find hook\n",
                                 e.offset, path.c_str(), path.c_str());
                        detail += line;
                        break;
                    }
                }
                close(fd);
            }
        }
        bool mf_ok = map_files_any_ok(maps);
        crc_target_map_files(maps, path, mf_ok, &issues, &detail);
        crc_pt_load_range(maps, path, segs, &issues, &detail);
        crc_checkfile_uid(path, maps, &issues, &detail);
    }
    crc_self_mapping(&issues, &detail);
    p.hit = issues > 0;
    if (detail.empty()) detail = "no libc/linker to crc";
    p.detail = "checked=" + std::to_string(checked) + " issues=" + std::to_string(issues) +
               " sdk=" + std::to_string(sdk) + "\n" + detail;
    return p;
}

std::string crc_report() {
    Probe p = run_crc_check();
    return std::string(p.hit ? "hit=1 " : "hit=0 ") + p.detail;
}

static std::string g_iso_crc, g_twin_crc;

void set_proc_crc(const std::string& iso, const std::string& twin) {
    g_iso_crc = iso;
    g_twin_crc = twin;
}

Probe probe_elf_crc() { return run_crc_check(); }

static Probe crc_from_blob(const std::string& blob, const char* who) {
    Probe p;
    if (blob.empty() || blob.find("timeout") != std::string::npos || blob.find("bind_fail") != std::string::npos) {
        p.detail = std::string(who) + " crc unavailable: " + (blob.empty() ? "empty" : blob);
        return p;
    }
    p.hit = blob.find("hit=1") == 0 || blob.find("pre-check") != std::string::npos ||
            blob.find(" MISMATCH") != std::string::npos || blob.find("find hook") != std::string::npos;
    p.detail = blob;
    return p;
}

Probe probe_iso_crc() { return crc_from_blob(g_iso_crc, "ISO"); }
Probe probe_twin_crc() { return crc_from_blob(g_twin_crc, "TWIN"); }

static std::string crc_sum_token(const std::string& blob, const char* needle) {
    auto pos = blob.find(needle);
    if (pos == std::string::npos) return {};
    auto m = blob.find("bytesum=", pos);
    if (m == std::string::npos || m > pos + 280) {
        m = blob.find(" mem=", pos);
        if (m == std::string::npos || m > pos + 240) return {};
        return blob.substr(m + 5, 8);
    }
    auto end = blob.find_first_of(" \n", m + 8);
    if (end == std::string::npos) end = m + 24;
    return blob.substr(m + 8, end - (m + 8));
}

Probe probe_crc_locality() {
    Probe p;
    std::string main = crc_report();
    const auto& iso = g_iso_crc;
    const auto& twin = g_twin_crc;
    std::string d;
    d += " remote compare crc start\n";
    d += "get iso crc info -> ";
    d += iso.substr(0, 160);
    d += "\nloction crc info  [main] -> ";
    d += main.substr(0, 160);
    d += "\nlocality crc -> ";
    d += main.substr(0, 120);
    d += "\nremote service crc -> ";
    d += iso.substr(0, 120);
    d += "\ntwin crc -> ";
    d += twin.substr(0, 120);
    d += '\n';
    if (iso.empty() || iso.find("timeout") != std::string::npos || iso.find("bind_fail") != std::string::npos) {
        p.detail = d + "Location CRC map is empty";
        return p;
    }
    int diffs = 0, compared = 0;
    for (auto* n : {"/libc.so", "/linker64", "/libart.so"}) {
        auto a = crc_sum_token(main, n);
        auto b = crc_sum_token(iso, n);
        if (a.empty() || b.empty()) continue;
        compared++;
        if (a != b) {
            diffs++;
            d += n;
            d += " locality=";
            d += a;
            d += " remote=";
            d += b;
            d += '\n';
        }
    }
    bool main_hook = main.find("find hook") != std::string::npos;
    bool iso_hook = iso.find("find hook") != std::string::npos;
    bool twin_hook = !twin.empty() && twin.find("timeout") == std::string::npos &&
                     twin.find("find hook") != std::string::npos;
    if (main_hook != iso_hook || (twin.find("timeout") == std::string::npos && !twin.empty() && main_hook != twin_hook)) {
        diffs++;
        d += "find-hook locality vs remote\n";
    }
    p.hit = diffs > 0;
    if (p.hit) d += "ISO CRC NOT MATCH LOCALITY CRC\n";
    d += " remote compare crc finish\n";
    p.detail = d;
    return p;
}

Probe probe_iso_unknown_exec() {
    Probe p;
    const auto& iso = isolate_snap();
    int unk = snap_field(iso, "unk");
    p.detail = "isolate ";
    p.detail += iso.empty() ? "empty" : iso;
    auto mp = iso.find("misspages=");
    if (mp != std::string::npos) {
        p.detail += "\n";
        p.detail += iso.substr(mp, 240);
    }
    // The iso loop thread is created with mainPid= and scans this
    // process's maps (SO: "native iso loop thread create start mainPid=").
    Probe loop = probe_unknown_exec();
    if (unk > 0) {
        p.hit = true;
        p.detail += "\nmissing page, suspicious execution procedure -> unk=";
        p.detail += std::to_string(unk);
    }
    if (loop.hit) {
        p.hit = true;
        p.detail += "\nISO Loop Thread Check Mem Error\n";
        p.detail += loop.detail;
    }
    if (!p.hit) {
        if (iso.empty() || iso.find("timeout") != std::string::npos) {
            p.detail += "\niso unknown-exec unavailable";
        } else {
            p.detail += "\nexec maps in whitelist";
        }
    }
    return p;
}

static bool kernel_id_dirty(const char* s) {
    if (!s || !*s) return false;
    return strstr(s, "dirty") || strstr(s, "maybe-dirty") || strstr(s, "Toybox");
}

// "Active VMA state machine: mmap -> maps -> mprotect -> maps -> munmap -> maps."
// Availability of mmap/memfd/PR_SET_VMA never independently changes the verdict.
// Hit only when a successful state-changing syscall is followed by an impossible maps observation.
static int vma_anon_state_machine(std::string* d) {
    long ps = sysconf(_SC_PAGESIZE);
    if (ps < 4096) ps = 4096;
    size_t n = (size_t)ps * 3;
    void* p = mmap(nullptr, n, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        *d += "anonymous mmap unavailable errno=";
        *d += std::to_string(errno);
        *d += '\n';
        return 0;
    }
    const char* nm = "icheck.vma.sm";
    int named = prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, (unsigned long)p, n, (unsigned long)nm);
    auto maps1 = parse_maps();
    const MapEnt* v1 = vma_at(maps1, (unsigned long)p);
    if (!v1) {
        munmap(p, n);
        *d += "anonymous mmap succeeded but mapping absent from maps\n";
        return 1;
    }
    auto blob1 = read_file("/proc/self/maps");
    if (named == 0 && blob1.find(nm) == std::string::npos) {
        *d += "anonymous mmap named mapping missing from maps\n";
        munmap(p, n);
        return 1;
    }
    void* mid = (char*)p + ps;
    if (mprotect(mid, (size_t)ps, PROT_READ | PROT_WRITE) != 0) {
        *d += "anonymous mprotect middle RW unavailable errno=";
        *d += std::to_string(errno);
        *d += '\n';
    } else {
        auto maps2 = parse_maps();
        const MapEnt* v2 = vma_at(maps2, (unsigned long)mid);
        if (!v2 || v2->perms[1] != 'w') {
            *d += "anonymous mprotect middle RW succeeded but maps perms lack w\n";
            munmap(p, n);
            return 1;
        }
        if (mprotect(mid, (size_t)ps, PROT_READ) != 0) {
            *d += "anonymous mprotect restore R unavailable errno=";
            *d += std::to_string(errno);
            *d += '\n';
        }
    }
    unsigned long addr = (unsigned long)p;
    unsigned long end = addr + n;
    if (munmap(p, n) != 0) {
        *d += "anonymous munmap unavailable errno=";
        *d += std::to_string(errno);
        *d += '\n';
        return 0;
    }
    auto blob3 = read_file("/proc/self/maps");
    if (named == 0 && blob3.find(nm) != std::string::npos) {
        *d += "anonymous munmap succeeded but the uniquely named mapping remains: ";
        *d += nm;
        *d += '\n';
        return 1;
    }
    auto maps3 = parse_maps();
    const MapEnt* v3 = vma_at(maps3, addr);
    if (v3 && v3->start == addr && v3->end == end && v3->inode == 0) {
        *d += "anonymous munmap succeeded but the uniquely named mapping remains\n";
        return 1;
    }
    *d += "Active VMA state machine: mmap -> maps -> mprotect -> maps -> munmap -> maps. anon=ok\n";
    return 0;
}

static int vma_memfd_state_machine(std::string* d) {
    long ps = sysconf(_SC_PAGESIZE);
    if (ps < 4096) ps = 4096;
    size_t n = (size_t)ps * 3;
    int fd = (int)syscall(__NR_memfd_create, "icheckmfd", MFD_CLOEXEC);
    if (fd < 0) {
        *d += "memfd_create unavailable errno=";
        *d += std::to_string(errno);
        *d += '\n';
        return 0;
    }
    if (ftruncate(fd, (off_t)n) != 0) {
        *d += "memfd ftruncate unavailable errno=";
        *d += std::to_string(errno);
        *d += '\n';
        close(fd);
        return 0;
    }
    struct stat st {};
    if (fstat(fd, &st) != 0) {
        *d += "memfd fstat unavailable errno=";
        *d += std::to_string(errno);
        *d += '\n';
        close(fd);
        return 0;
    }
    void* p = mmap(nullptr, n, PROT_READ, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        *d += "memfd mmap unavailable errno=";
        *d += std::to_string(errno);
        *d += '\n';
        close(fd);
        return 0;
    }
    auto maps1 = parse_maps();
    const MapEnt* v1 = vma_at(maps1, (unsigned long)p);
    if (!v1) {
        munmap(p, n);
        close(fd);
        *d += "memfd mmap succeeded but mapping absent from maps\n";
        return 1;
    }
    unsigned long ino = v1->inode;
    unsigned maj = v1->devmaj, minv = v1->devmin;
    unsigned long off = v1->offset;
    unsigned long addr = (unsigned long)p;
    unsigned long end = addr + n;
    char mf[96];
    snprintf(mf, sizeof(mf), "/proc/self/map_files/%lx-%lx", v1->start, v1->end);
    int mfd = open(mf, O_RDONLY | O_CLOEXEC);
    if (mfd < 0) {
        // map_files availability never independently changes the verdict.
        *d += ": map_files readlink unavailable errno=";
        *d += std::to_string(errno);
        *d += '\n';
    } else {
        close(mfd);
        *d += "map_files matched line: ";
        *d += mf;
        *d += '\n';
    }
    void* mid = (char*)p + ps;
    if (mprotect(mid, (size_t)ps, PROT_READ | PROT_WRITE) != 0) {
        *d += "memfd mprotect middle RW unavailable errno=";
        *d += std::to_string(errno);
        *d += '\n';
    } else {
        auto maps2 = parse_maps();
        const MapEnt* v2 = vma_at(maps2, (unsigned long)mid);
        if (!v2 || v2->perms[1] != 'w') {
            *d += "memfd mprotect middle RW succeeded but maps perms lack w\n";
            munmap(p, n);
            close(fd);
            return 1;
        }
        mprotect(mid, (size_t)ps, PROT_READ);
    }
    if (munmap(p, n) != 0) {
        *d += "memfd munmap unavailable errno=";
        *d += std::to_string(errno);
        *d += '\n';
        close(fd);
        return 0;
    }
    auto maps3 = parse_maps();
    for (auto& e : maps3) {
        if (e.start == addr && e.end == end && e.inode == ino && e.devmaj == maj && e.devmin == minv &&
            e.offset == off) {
            *d += ": munmap succeeded but the same memfd mapping remains: inode=";
            *d += std::to_string(ino);
            *d += '\n';
            close(fd);
            return 1;
        }
    }
    (void)st;
    close(fd);
    *d += "Active VMA state machine: mmap -> maps -> mprotect -> maps -> munmap -> maps. memfd=ok\n";
    return 0;
}

Probe probe_kernel_runtime() {
    Probe p;
    struct utsname ul {}, ur {};
    uname(&ul);
    long urc = svc5(SYS_uname, (long)&ur, 0, 0, 0, 0);
    bool raw_ok = !(urc < 0 && urc >= -4095);
    auto os = read_file("/proc/sys/kernel/osrelease", 128);
    while (!os.empty() && (os.back() == '\n' || os.back() == '\r')) os.pop_back();
    auto ver = read_file("/proc/version", 256);
    long pgsz = sysconf(_SC_PAGESIZE);
    int gp = getpagesize();
    unsigned long auxp = getauxval(AT_PAGESZ);
    pid_t pid = getpid();
    long pid_raw = svc5(SYS_getpid, 0, 0, 0, 0, 0);
    auto pmaxs = read_file("/proc/sys/kernel/pid_max", 32);
    long pmax = atol(pmaxs.c_str());
    int nnp_pr = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    long nnp_raw = svc5(SYS_prctl, PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    int sc_pr = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    long sc_raw = svc5(SYS_prctl, PR_GET_SECCOMP, 0, 0, 0, 0);
    auto st = read_file("/proc/self/status", 4096);
    auto st_i = [&](const char* k) {
        auto pos = st.find(k);
        return pos == std::string::npos ? -1 : atoi(st.c_str() + pos + strlen(k));
    };
    int nnp_st = st_i("NoNewPrivs:");
    int sc_st = st_i("Seccomp:");
    char buf[768];
    snprintf(buf, sizeof(buf),
             "raw uname release=%s libc=%s osrelease=%s\n"
             "AT_PAGESZ vs getpagesize() auxp=%lu gp=%d sysconf=%ld\n"
             "impossiblePid= libc=%d raw=%ld pid_max=%ld\n"
             "NoNewPrivs: pr=%d raw=%ld st=%d\n"
             "Seccomp pr=%d raw=%ld st=%d",
             raw_ok ? ur.release : "-", ul.release, os.c_str(), auxp, gp, pgsz, (int)pid, pid_raw, pmax, nnp_pr,
             nnp_raw, nnp_st, sc_pr, sc_raw, sc_st);
    p.detail = buf;
    if (raw_ok && ur.release[0] && strcmp(ul.release, ur.release) != 0) {
        p.hit = true;
        p.detail += "\nlibc/raw uname diverge";
    }
    if (!os.empty() && os != ul.release) {
        p.hit = true;
        p.detail += "\nuname vs osrelease diverge";
    }
    if (auxp && gp > 0 && (unsigned long)gp != auxp) {
        p.hit = true;
        p.detail += "\nAT_PAGESZ vs getpagesize()";
    }
    if (pgsz > 0 && gp > 0 && pgsz != gp) {
        p.hit = true;
        p.detail += "\nAT_PAGESZ vs sysconf(_SC_PAGESIZE)";
    }
    if (pid_raw > 0 && pid_raw != pid) {
        p.hit = true;
        p.detail += "\ngetpid libc/raw";
    }
    if (pmax > 0 && ((long)pid >= pmax || pid < 1 || (pid_raw > 0 && pid_raw >= pmax))) {
        p.hit = true;
        p.detail += "\nimpossiblePid";
    }
    if (nnp_st >= 0 && nnp_pr >= 0 && nnp_st != nnp_pr) {
        p.hit = true;
        p.detail += "\nthread procfs NoNewPrivs vs raw prctl";
    }
    if (nnp_raw >= 0 && nnp_raw < 256 && nnp_pr >= 0 && nnp_raw != nnp_pr) {
        p.hit = true;
        p.detail += "\nNoNewPrivs libc/raw";
    }
    if (sc_st >= 0 && sc_pr >= 0 && sc_st != sc_pr) {
        p.hit = true;
        p.detail += "\nSeccomp libc vs procfs";
    }
    if (sc_raw >= 0 && sc_raw < 256 && sc_pr >= 0 && sc_raw != sc_pr) {
        p.hit = true;
        p.detail += "\nSeccomp libc/raw";
    }
    // Unreadable /proc/sys/kernel/* (SELinux) is not a spoof. Only compare
    // dirty bits when both sides actually produced text.
    if (!ver.empty() && kernel_id_dirty(ul.release) != kernel_id_dirty(ver.c_str())) {
        p.hit = true;
        p.detail += "\n/proc/version vs uname dirty split";
    }
    if (raw_ok && ur.release[0] && kernel_id_dirty(ur.release) != kernel_id_dirty(ul.release)) {
        p.hit = true;
        p.detail += "\nlibc/raw uname dirty split";
    }
    // Kernel Runtime on redroid: uname.version carries Toybox (container
    // uname) against a spoofed user/release-keys identity.
    if (strstr(ul.version, "Toybox") || (raw_ok && strstr(ur.version, "Toybox"))) {
        p.hit = true;
        p.detail += "\nuname.version Toybox";
    }
    const auto& iso = isolate_snap();
    if (!iso.empty() && iso.find("timeout") == std::string::npos) {
        auto ru = snap_str(iso, "rawuname");
        auto lu = snap_str(iso, "uname");
        if (!ru.empty() && ru != "-" && !lu.empty() && ru != lu) {
            p.hit = true;
            p.detail += "\nisolate libc/raw uname diverge";
        }
    }
    if (os.empty()) {
        p.detail += "\n/proc/sys/kernel/osrelease unavailable errno=";
        int osfd = open("/proc/sys/kernel/osrelease", O_RDONLY | O_CLOEXEC);
        if (osfd < 0) p.detail += std::to_string(errno);
        else close(osfd);
        // unreadable osrelease is not a spoof by itself
    }
    p.detail += '\n';
    if (vma_anon_state_machine(&p.detail)) p.hit = true;
    if (vma_memfd_state_machine(&p.detail)) p.hit = true;
    pid_t bad = (pmax > 1) ? (pid_t)(pmax + 1) : (pid_t)0x7ffffffe;
    errno = 0;
    long seize = ptrace(PTRACE_SEIZE, bad, nullptr, nullptr);
    if (seize == 0) {
        p.hit = true;
        p.detail += "PTRACE_SEIZE unexpectedly succeeded for impossible pid=";
        p.detail += std::to_string((int)bad);
        p.detail += '\n';
        ptrace(PTRACE_DETACH, bad, nullptr, nullptr);
    }
    if (p.hit) p.detail += "\nKernel Runtime Consistency Violation";
    else p.detail += "Kernel Runtime Consistency Check";
    return p;
}

static int appid_of(int uid) { return uid % 100000; }

// AOSP isolatedProcess: 99000-99999. App-zygote isolated: 90000-98999.
static bool legal_isolated_appid(int ia) {
    return (ia >= 90000 && ia <= 98999) || (ia >= 99000 && ia <= 99999);
}

Probe probe_hide_uid() {
    Probe p;
    uid_t uid = getuid();
    long uid_raw = svc5(SYS_getuid, 0, 0, 0, 0, 0);
    auto st = read_file("/proc/self/status", 4096);
    int suid = -1;
    auto us = st.find("Uid:");
    if (us != std::string::npos) suid = atoi(st.c_str() + us + 4);
    int aid = appid_of((int)uid);
    auto se = read_file("/proc/self/attr/current", 256);
    bool iso_ctx = se.find("isolated_app") != std::string::npos;
    std::string d;
    char buf[192];
    snprintf(buf, sizeof(buf), "uid=%d raw=%ld status_Uid=%d appid=%d se=%s", (int)uid, uid_raw, suid, aid,
             se.c_str());
    d = buf;
    if (suid >= 0 && (uid_t)suid != uid) {
        p.hit = true;
        d += "\ngetuid vs /proc/self/status Uid";
    }
    if (uid_raw >= 0 && uid_raw < 1000000000L && (uid_t)uid_raw != uid) {
        p.hit = true;
        d += "\ngetuid libc/raw";
    }
    if (iso_ctx && !legal_isolated_appid(aid)) {
        p.hit = true;
        d += "\nisolated_app uid not in 90000-99999";
    }
    const auto& iso = isolate_snap();
    int iuid = snap_field(iso, "uid");
    auto ise = snap_str(iso, "se");
    if (iuid >= 0) {
        int ia = appid_of(iuid);
        d += "\nisolate uid=";
        d += std::to_string(iuid);
        d += " se=";
        d += ise;
        bool iso_app = ise.find("isolated_app") != std::string::npos;
        // Own app-zygote isolate in 90000-98999 is stock, not Magisk hide.
        if (iso_app && !legal_isolated_appid(ia)) {
            p.hit = true;
            d += " isolate isolated_app with illegal uid";
        }
        if (!iso_app && ia >= 90000 && ia <= 98999) {
            p.hit = true;
            d += " isolate hide-uid (not isolated_app)";
        }
    }
    // hidepid=invisible hides foreign pids from readdir(/proc) but /proc/<pid>/status
    // is still readable if the pid is known — walk the pid namespace.
    long pmax = atol(read_file("/proc/sys/kernel/pid_max", 32).c_str());
    if (pmax <= 1) pmax = 32768;
    if (pmax > 65535) pmax = 65535;
    int hide_n = 0;
    std::string found;
    for (int pid = 1; pid <= (int)pmax; pid++) {
        char sp[64];
        snprintf(sp, sizeof(sp), "/proc/%d/status", pid);
        auto body = read_file(sp, 256);
        auto pos = body.find("Uid:");
        if (pos == std::string::npos) continue;
        int pu = atoi(body.c_str() + pos + 4);
        int pa = appid_of(pu);
        if (pa < 90000 || pa >= 99000) continue;
        if ((uid_t)pu == uid) continue;
        if (iuid >= 0 && pu == iuid) continue;
        hide_n++;
        if (found.size() < 180) {
            found += std::to_string(pid);
            found += "=";
            found += std::to_string(pu);
            found += " ";
        }
    }
    if (hide_n > 0) {
        p.hit = true;
        d += "\nproc hide-uid n=";
        d += std::to_string(hide_n);
        d += " ";
        d += found;
    }
    if (p.hit) d += "\nFind Hide Uid";
    p.detail = d;
    return p;
}

Probe probe_selinux_isolation() {
    Probe p;
    auto se = read_file("/proc/self/attr/current", 256);
    while (!se.empty() && (unsigned char)se.back() <= ' ') se.pop_back();
    const auto& iso = isolate_snap();
    const auto& twin = twin_snap();
    auto ise = snap_str(iso, "se");
    auto tse = snap_str(twin, "se");
    int iuid = snap_field(iso, "uid");
    int innp = snap_field(iso, "nnp_st");
    if (innp < 0) innp = snap_field(iso, "nnp_pr");
    int isc = snap_field(iso, "sc_st");
    if (isc < 0) isc = snap_field(iso, "sc_pr");
    int tsc = snap_field(twin, "sc_st");
    if (tsc < 0) tsc = snap_field(twin, "sc_pr");
    std::string d = "main se=" + (se.empty() ? std::string("-") : se);
    d += "\nisolate se=";
    d += ise.empty() ? "-" : ise;
    d += " uid=";
    d += std::to_string(iuid);
    d += " nnp=";
    d += std::to_string(innp);
    d += " sc=";
    d += std::to_string(isc);
    d += "\ntwin se=";
    d += tse.empty() ? "-" : tse;
    d += " sc=";
    d += std::to_string(tsc);
    if (!iso.empty() && iso.find("timeout") == std::string::npos && iso.find("bind_fail") == std::string::npos) {
        if (ise.find("isolated_app") == std::string::npos && ise != "-" && !ise.empty()) {
            p.hit = true;
            d += "\nisolate secontext is not isolated_app";
        }
        if (iuid >= 0) {
            int ia = appid_of(iuid);
            if (!legal_isolated_appid(ia)) {
                p.hit = true;
                d += "\nisolate uid not in isolated range";
            }
        }
        if (innp == 0) {
            p.hit = true;
            d += "\nisolate NoNewPrivs=0";
        }
    }
    if (ise.find("su") != std::string::npos || tse.find(":su:") != std::string::npos ||
        se.find(":su:") != std::string::npos) {
        p.hit = true;
        d += "\nsecontext su";
    }
    if (!twin.empty() && twin.find("timeout") == std::string::npos) {
        if (tse.find("isolated_app") != std::string::npos) {
            int tuid = snap_field(twin, "uid");
            if (tuid >= 0 && !legal_isolated_appid(appid_of(tuid))) {
                p.hit = true;
                d += "\ntwin isolated_app with illegal uid";
            }
        }
        if (tsc == 0 && isc == 0) {
            // both missing seccomp is a runtime isolation failure on AOSP (apps are mode 2)
            p.hit = true;
            d += "\ntwin/isolate Seccomp=0";
        }
        if (p.hit) d += "\nSELinux Runtime Isolation Violation (twin)";
    } else if (p.hit) {
        d += "\nSELinux Runtime Isolation Violation";
    }
    p.detail = d;
    return p;
}

Probe probe_maps_unread() {
    Probe p;
    int bad = 0;
    std::string d;
    for (auto& e : parse_maps()) {
        if (e.path.empty() || e.path[0] != '/') continue;
        if (strchr(e.perms, 'r')) continue;
        // A10+ XOM: libc/libcrypto often mapped --xp. That is stock, not a hide.
        if (e.path.find("/system/") == 0 || e.path.find("/apex/") == 0 ||
            e.path.find("/vendor/") == 0 || e.path.find("/product/") == 0)
            continue;
        if (e.path.find(".so") == std::string::npos && e.path.find("linker") == std::string::npos) continue;
        bad++;
        if (d.size() < 400) {
            d += e.path;
            d += " ";
            d += e.perms;
            d += '\n';
        }
    }
    p.hit = bad > 0;
    p.detail = p.hit ? ("non-readable file-backed so: " + std::to_string(bad) + "\n" + d)
                     : "no non-readable so VMA";
    return p;
}

static bool stock_exec(const std::string& path) {
    if (path.find("[vdso]") != std::string::npos || path.find("[vvar]") != std::string::npos ||
        path.find("[uprobes]") != std::string::npos || path.find("[sigpage]") != std::string::npos)
        return true;
    if (path.find("memfd:jit-cache") != std::string::npos ||
        path.find("memfd:jit-zygote-cache") != std::string::npos ||
        path.find("jit-cache") != std::string::npos || path.find("jit-zygote-cache") != std::string::npos)
        return true;
    if (path.find("/data/app/") != std::string::npos || path.find("/data/dalvik-cache/") != std::string::npos)
        return true;
    if (path.find("/system/") == 0 || path.find("/apex/") == 0 || path.find("/vendor/") == 0 ||
        path.find("/product/") == 0 || path.find("/system_ext/") == 0)
        return true;
    return false;
}

Probe probe_unknown_exec() {
    Probe p;
    int unk = 0, rwx = 0;
    std::string d, misspages;
    for (auto& e : parse_maps()) {
        if (!strchr(e.perms, 'x')) continue;
        const std::string& path = e.path;
        bool is_rwx = strchr(e.perms, 'r') && strchr(e.perms, 'w') && strchr(e.perms, 'x');
        if (is_rwx && !stock_exec(path)) {
            rwx++;
            if (d.size() < 600) {
                d += "find rwx item ";
                d += path.empty() ? "?" : path;
                d += " ";
                d += e.perms;
                d += '\n';
            }
        }
        // "missing page": executable VMA with no pathname (not vdso/jit).
        bool missing = path.empty() || path[0] == '\0';
        if (missing) {
            unk++;
            char line[96];
            snprintf(line, sizeof(line),
                     "exec address start-> 0x%lx\nexec address end-> 0x%lx\nmem size -> %lu\n", e.start, e.end,
                     e.end - e.start);
            if (d.size() < 800) {
                d += "------------------------------\n";
                d += line;
            }
            if (misspages.size() < 180) {
                char mp[48];
                snprintf(mp, sizeof(mp), "%lx-%lx ", e.start, e.end);
                misspages += mp;
            }
        } else if (!stock_exec(path) && path[0] == '/' &&
                   (path.find("/data/adb/") != std::string::npos || path.find("dobby") != std::string::npos ||
                    path.find("lsposed") != std::string::npos || path.find("riru") != std::string::npos ||
                    path.find("lsplant") != std::string::npos)) {
            unk++;
            if (d.size() < 800) {
                d += path;
                d += " unsafe executable mapping perms=";
                d += e.perms;
                d += '\n';
            }
        }
    }
    p.hit = unk > 0 || rwx > 0;
    if (!p.hit) {
        p.detail = "unknown=0 rwx=0 exec maps in whitelist";
        return p;
    }
    p.detail = "unknown=" + std::to_string(unk) + " rwx=" + std::to_string(rwx);
    if (!misspages.empty()) {
        p.detail += " misspages=";
        p.detail += misspages;
    }
    p.detail += "\nmissing page, suspicious execution procedure -> \n";
    p.detail += d;
    return p;
}

Probe probe_embedded_elf() {
    Probe p;
    int n = 0;
    for (auto& e : parse_maps()) {
        if (!strchr(e.perms, 'x')) continue;
        if (!e.path.empty() && e.path[0] == '/') continue;
        if (e.path.find("[vdso]") != std::string::npos || e.path.find("jit") != std::string::npos) continue;
        if (e.end <= e.start || e.end - e.start < 0x10000) continue;
        if (!strchr(e.perms, 'r')) continue;
        unsigned char mag[4] = {};
        memcpy(mag, (void*)e.start, 4);
        if (mag[0] == 0x7f && mag[1] == 'E' && mag[2] == 'L' && mag[3] == 'F') {
            n++;
            p.detail += "anon ELF @" + std::to_string(e.start) + "\n";
        }
    }
    p.hit = n > 0;
    if (!p.hit) p.detail = "no anonymous ELF exec";
    return p;
}

Probe probe_odex() {
    Probe p;
    int n = 0;
    for (auto& e : parse_maps()) {
        if (e.path.find(".odex") == std::string::npos && e.path.find(".oat") == std::string::npos &&
            e.path.find(".vdex") == std::string::npos)
            continue;
        if (!strchr(e.perms, 'x')) continue;
        bool ok = e.path.find("/dalvik-cache/") != std::string::npos ||
                  e.path.find("/apex/") != std::string::npos ||
                  e.path.find("/data/app/") != std::string::npos ||
                  e.path.find("/system/") == 0 ||
                  e.path.find("/system_ext/") == 0 ||
                  e.path.find("/product/") == 0 ||
                  e.path.find("/vendor/") == 0 ||
                  e.path.find("/odm/") == 0;
        if (!ok) {
            n++;
            p.detail += e.path + "\n";
        }
    }
    p.hit = n > 0;
    if (!p.hit) p.detail = "odex/oat maps expected";
    return p;
}

Probe probe_inline_hook() {
    Probe p;
    auto maps = read_file("/proc/self/maps");
    static const char* keys[] = {"dobby", "Dobby", "lspatch", "sandhook", "And64InlineHook",
                                 "libhook", "libwhale", "shadowhook", "bytehook", nullptr};
    for (int i = 0; keys[i]; i++) {
        if (maps.find(keys[i]) != std::string::npos) {
            p.hit = true;
            p.detail += keys[i];
            p.detail += " in maps\n";
        }
    }
    unsigned long libc = 0;
    for (auto& e : parse_maps()) {
        if (e.path.find("libc.so") == std::string::npos || !strchr(e.perms, 'x')) continue;
        if (!strchr(e.perms, 'r')) continue;
        libc = e.start;
        break;
    }
    if (libc) {
        uint32_t w = 0, w1 = 0;
        memcpy(&w, (void*)libc, 4);
        memcpy(&w1, (void*)(libc + 4), 4);
        if (w1 == 0xD61F0200u && (w & 0xFF00001Fu) == 0x58000010u) {
            p.hit = true;
            p.detail += "libc x-base trampoline\n";
        }
    }
    for (auto& e : parse_maps()) {
        if (e.path.find("libart.so") == std::string::npos || !strchr(e.perms, 'x')) continue;
        // A10+ XOM maps libart --xp. Reading it is SEGV_ACCERR (Meizu 17).
        if (!strchr(e.perms, 'r')) continue;
        size_t len = e.end - e.start;
        if (len > 4096) len = 4096;
        const uint32_t* ins = (const uint32_t*)e.start;
        int hooks = 0;
        for (size_t i = 0; i + 1 < len / 4; i++) {
            uint32_t a = ins[i], b = ins[i + 1];
            if (b == 0xD61F0200u && (a & 0xFF000000u) == 0x58000000u) hooks++;
        }
        if (hooks > 8) {
            p.hit = true;
            p.detail += "libart trampoline_count=" + std::to_string(hooks) + "\n";
        }
        break;
    }
    if (!p.hit) p.detail = p.detail.empty() ? "no dobby/trampoline" : p.detail;
    return p;
}

Probe probe_hwbp() {
    Probe p;
    pid_t child = fork();
    if (child < 0) {
        p.detail = "fork fail";
        return p;
    }
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        raise(SIGSTOP);
        _exit(0);
    }
    int st = 0;
    bool stopped = false;
    for (int i = 0; i < 50; i++) {
        pid_t w = waitpid(child, &st, WUNTRACED | WNOHANG);
        if (w == child) {
            stopped = true;
            break;
        }
        usleep(20000);
    }
    if (!stopped) {
        kill(child, SIGKILL);
        waitpid(child, &st, WNOHANG);
        p.detail = "waitpid timeout";
        return p;
    }
    uint64_t regs[64] = {};
    struct iovec iov {};
    iov.iov_base = regs;
    iov.iov_len = sizeof(regs);
    int rc = ptrace(PTRACE_GETREGSET, child, (void*)(uintptr_t)NT_ARM_HW_BREAK, &iov);
    uint64_t wregs[64] = {};
    struct iovec wiov {};
    wiov.iov_base = wregs;
    wiov.iov_len = sizeof(wregs);
    int watch_rc = ptrace(PTRACE_GETREGSET, child, (void*)(uintptr_t)NT_ARM_HW_WATCH, &wiov);
    ptrace(PTRACE_DETACH, child, nullptr, nullptr);
    kill(child, SIGKILL);
    for (int i = 0; i < 20; i++) {
        if (waitpid(child, &st, WNOHANG) == child) break;
        usleep(10000);
    }
    int setn = 0;
    if (rc == 0) {
        for (size_t i = 1; i < 16 && i < iov.iov_len / 8; i++) {
            if (regs[i]) setn++;
        }
    }
    p.hit = setn > 0;
    char buf[192];
    snprintf(buf, sizeof(buf), "GETREGSET_hw_break rc=%d watch_rc=%d iov=%zu set_slots=%d",
             rc, watch_rc, iov.iov_len, setn);
    p.detail = buf;
    return p;
}

Probe probe_mmap_legality() {
    Probe p;
    size_t page = 4096;
    void* m = mmap(nullptr, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) {
        p.hit = true;
        p.detail = "mmap fail";
        return p;
    }
    auto maps1 = read_file("/proc/self/maps");
    char addr[32];
    snprintf(addr, sizeof(addr), "%lx-", (unsigned long)m);
    bool in1 = maps1.find(addr) != std::string::npos;
    if (mprotect(m, page, PROT_READ) != 0) {
        p.hit = true;
        p.detail = "mprotect fail";
        munmap(m, page);
        return p;
    }
    auto maps2 = read_file("/proc/self/maps");
    bool in2 = maps2.find(addr) != std::string::npos;
    munmap(m, page);
    auto maps3 = read_file("/proc/self/maps");
    bool in3 = maps3.find(addr) != std::string::npos;
    p.hit = !in1 || !in2 || in3;
    p.detail = std::string("mmap_in_maps=") + (in1 ? "1" : "0") +
               " after_mprotect=" + (in2 ? "1" : "0") +
               " after_munmap=" + (in3 ? "1" : "0");
    return p;
}

Probe probe_unidbg() {
    Probe p;
    auto maps = read_file("/proc/self/maps");
    auto cpu = read_file("/proc/cpuinfo", 2048);
    if (maps.find("unidbg") != std::string::npos) {
        p.hit = true;
        p.detail += "maps unidbg\n";
    }
    if (cpu.empty()) {
        p.hit = true;
        p.detail += "empty cpuinfo\n";
    }
    if (!exists_path("/sys/devices/system/cpu")) {
        p.hit = true;
        p.detail += "no cpu sysfs\n";
    }
    if (!exists_path("/proc/self/fd")) {
        p.hit = true;
        p.detail += "no /proc/self/fd\n";
    }
    long nproc = sysconf(_SC_NPROCESSORS_CONF);
    auto hw = prop("ro.hardware");
    if (hw.find("unidbg") != std::string::npos || hw.find("goldfish") != std::string::npos) {
        p.hit = true;
        p.detail += "hw=" + hw + "\n";
    }
    unsigned long aux = getauxval(AT_RANDOM);
    if (aux == 0) {
        p.hit = true;
        p.detail += "AT_RANDOM=0\n";
    }
    if (!p.hit) p.detail = "nproc=" + std::to_string(nproc) + " hw=" + hw + " no unidbg marks";
    return p;
}

#ifndef SYS_prctl
#define SYS_prctl 167
#endif
#ifndef SYS_getpid
#define SYS_getpid 172
#endif
#ifndef PR_GET_DUMPABLE
#define PR_GET_DUMPABLE 3
#endif
#define APATCH_PRCTL_MAGIC 0x11581158L

static TickStat bench_prctl(long opt, long cmd, int n) {
    uint64_t v[48];
    int m = n > 48 ? 48 : n;
    int32_t result = 0, ver = 0;
    for (int i = 0; i < m; i++) {
        uint64_t a = ticks_now();
        svc5(SYS_prctl, opt, cmd, (long)&ver, 0, (long)&result);
        uint64_t b = ticks_now();
        v[i] = b - a;
    }
    return ticks_stat(v, m, 5);
}

static TickStat bench_getpid(int n) {
    uint64_t v[48];
    int m = n > 48 ? 48 : n;
    for (int i = 0; i < m; i++) {
        uint64_t a = ticks_now();
        svc5(SYS_getpid, 0, 0, 0, 0, 0);
        uint64_t b = ticks_now();
        v[i] = b - a;
    }
    return ticks_stat(v, m, 5);
}

Probe probe_ksu_sidechannel() {
    Probe p;
    int32_t ver = 0, result_svc = 0, result_libc = 0;
    int32_t umount = 0, mgr = 0, hook = 0, kpm = 0;
    bool cookie_svc = ksu_ksuctl(2, &ver, nullptr, &result_svc);
    int32_t ver_l = 0;
    prctl((int)0xDEADBEEF, 2, &ver_l, nullptr, &result_libc);
    bool cookie_libc = result_libc == (int32_t)0xDEADBEEF || ver_l > 0;
    if (ver_l > 0 && ver == 0) ver = ver_l;
    int32_t r = 0;
    ksu_ksuctl(8, &umount, nullptr, &r);
    ksu_ksuctl(9, &mgr, nullptr, &r);
    ksu_ksuctl(10, &hook, nullptr, &r);
    ksu_ksuctl(13, &kpm, nullptr, &r);

    // Side channel: RWX probe times 4 groups, ratio vs baseline.
    // s   = getpid (cheap)
    // s1  = prctl(PR_GET_DUMPABLE)  — real kernel work, denominator
    // s2  = prctl(DEADBEEF, GET_VERSION)
    // s3  = prctl(DEADBEEF, BECOME_MANAGER)  — extra copy_from_user
    // s4  = prctl(0x11581158) APatch/KP hello
    const int N = 24;
    auto s0 = bench_getpid(N);
    auto s1 = bench_prctl(PR_GET_DUMPABLE, 0, N);
    auto s2 = bench_prctl((long)0xDEADBEEF, 2, N);
    auto s3 = bench_prctl((long)0xDEADBEEF, 1, N);
    auto s4 = bench_prctl(APATCH_PRCTL_MAGIC, 0, N);

    auto stable = [](const TickStat& t) { return t.avg > 0 && t.dev * 10.0 <= t.avg; };
    bool ok = stable(s0) && stable(s1) && stable(s2) && stable(s3);
    double den = s1.avg - s0.avg;
    double ratio0 = 0, ratio1 = 0, ratio_ap = 0;
    bool ksu_hi = false, ap_mid = false;
    if (ok && den > s0.avg * 0.02) {
        ratio0 = (s2.avg - s0.avg) / den;
        ratio1 = (s3.avg - s0.avg) / den;
        ratio_ap = (s4.avg - s0.avg) / den;
        // ratio>2.2 high latency; >1.4 mid latency
        if (ratio0 > 2.2 && ratio1 > 2.2) ksu_hi = true;
        else if (ratio0 > 1.4 && ratio1 > 1.4) ap_mid = true;
        if (ratio_ap > 1.4 && stable(s4)) ap_mid = true;
    }
    // Issue #300: even with rc=-1, BECOME_MANAGER is tens of µs slower.
    bool raw_slow = s3.avg > s1.avg * 2.0 && s3.avg > s0.avg * 3.0 && stable(s3);

    p.hit = cookie_svc || cookie_libc || umount != 0 || mgr > 0 || ksu_hi || ap_mid || raw_slow;
    char buf[512];
    snprintf(buf, sizeof(buf),
             "svc_cookie=%d libc_cookie=%d ver=%d umount=%d mgr=%d "
             "pid=%.0f dumpable=%.0f ksu_ver=%.0f ksu_mgr=%.0f ap=%.0f "
             "ratio0=%.3f ratio1=%.3f ratio_ap=%.3f %s",
             cookie_svc ? 1 : 0, cookie_libc ? 1 : 0, (int)ver, (int)umount, (int)mgr, s0.avg, s1.avg,
             s2.avg, s3.avg, s4.avg, ratio0, ratio1, ratio_ap,
             ksu_hi ? "KernelSU High Latency" : ap_mid ? "APatch/KP Mid Latency" : "no extra latency");
    p.detail = buf;
    if (cookie_svc && !cookie_libc) p.detail += "\nlibc prctl hooked, SVC cookie survives";
    const auto& iso = isolate_snap();
    if (!iso.empty() && snap_field(iso, "ksu_cookie") == 1 && !cookie_svc && !cookie_libc) {
        p.hit = true;
        p.detail += "\nisolate cookie, main none (userspace hide)";
    }
    if (!iso.empty() && snap_field(iso, "ksu_umount") == 1 && umount == 0) {
        p.hit = true;
        p.detail += "\nisolate uid_should_umount, main spoofed";
    }
    return p;
}

Probe probe_avc_log() {
    Probe p;
    std::string blob;
    // klogctl (syslog syscall 116) is SIGSYS/seccomp on untrusted_app.
    int fd = open("/proc/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd >= 0) {
        char tmp[4096];
        ssize_t n;
        while ((n = read(fd, tmp, sizeof(tmp))) > 0) {
            blob.append(tmp, (size_t)n);
            if (blob.size() > 64 * 1024) break;
        }
        close(fd);
    }
    if (blob.empty()) blob = read_file("/proc/last_kmsg", 64 * 1024);
    int hits = 0;
    const char* keys[] = {"avc:  denied", "avc: denied", "untrusted_app", nullptr};
    if (!blob.empty()) {
        for (int i = 0; keys[i]; i++) {
            if (blob.find(keys[i]) != std::string::npos) hits++;
        }
    }
    auto sel = read_file("/sys/fs/selinux/enforce");
    p.hit = blob.find("avc:  denied") != std::string::npos || blob.find("avc: denied") != std::string::npos;
    p.detail = "klog_bytes=" + std::to_string(blob.size()) + " avc_hits=" + std::to_string(hits) +
               " enforce=" + sel;
    if (blob.empty()) p.detail += " (klog unreadable — probed)";
    return p;
}

static uintptr_t linker_load_base(const char* needle) {
    unsigned long lo = 0;
    for (auto& e : parse_maps()) {
        if (e.path.find(needle) == std::string::npos) continue;
        if (!lo || e.start < lo) lo = e.start;
    }
    return (uintptr_t)lo;
}

static uintptr_t elf_lookup(const char* path, uintptr_t load_base, const char* name) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    off_t sz = lseek(fd, 0, SEEK_END);
    if (sz < 64) {
        close(fd);
        return 0;
    }
    lseek(fd, 0, SEEK_SET);
    std::vector<uint8_t> file((size_t)sz);
    if (read(fd, file.data(), (size_t)sz) != sz) {
        close(fd);
        return 0;
    }
    close(fd);
    auto* eh = (Elf64_Ehdr*)file.data();
    if (eh->e_ident[EI_CLASS] != ELFCLASS64) return 0;
    auto* ph = (Elf64_Phdr*)(file.data() + eh->e_phoff);
    uint64_t min_vaddr = UINT64_MAX;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD && ph[i].p_vaddr < min_vaddr) min_vaddr = ph[i].p_vaddr;
    }
    if (min_vaddr == UINT64_MAX) min_vaddr = 0;
    uintptr_t bias = load_base - (uintptr_t)min_vaddr;
    auto* sh = (Elf64_Shdr*)(file.data() + eh->e_shoff);
    const char* shstr = nullptr;
    if (eh->e_shstrndx && eh->e_shstrndx < eh->e_shnum)
        shstr = (const char*)(file.data() + sh[eh->e_shstrndx].sh_offset);
    auto scan = [&](Elf64_Shdr* symsh, Elf64_Shdr* strsh) -> uintptr_t {
        if (!symsh || !strsh) return 0;
        if (symsh->sh_offset + symsh->sh_size > file.size()) return 0;
        if (strsh->sh_offset + strsh->sh_size > file.size()) return 0;
        auto* sym = (Elf64_Sym*)(file.data() + symsh->sh_offset);
        const char* str = (const char*)(file.data() + strsh->sh_offset);
        size_t count = symsh->sh_entsize ? (symsh->sh_size / symsh->sh_entsize)
                                         : (symsh->sh_size / sizeof(Elf64_Sym));
        for (size_t i = 0; i < count; i++) {
            if (!sym[i].st_name || sym[i].st_name >= strsh->sh_size) continue;
            if (strcmp(str + sym[i].st_name, name) == 0 && sym[i].st_value)
                return bias + (uintptr_t)sym[i].st_value;
        }
        return 0;
    };
    Elf64_Shdr *dynsym = nullptr, *symtab = nullptr, *dynstr = nullptr, *strtab = nullptr;
    for (int i = 0; i < eh->e_shnum; i++) {
        const char* sname = (shstr && sh[i].sh_name) ? shstr + sh[i].sh_name : "";
        if (sh[i].sh_type == SHT_DYNSYM) {
            dynsym = &sh[i];
            if (sh[i].sh_link < eh->e_shnum) dynstr = &sh[sh[i].sh_link];
        }
        if (sh[i].sh_type == SHT_SYMTAB && strcmp(sname, ".symtab") == 0) {
            symtab = &sh[i];
            if (sh[i].sh_link < eh->e_shnum) strtab = &sh[sh[i].sh_link];
        }
        if (sh[i].sh_type == SHT_STRTAB && strcmp(sname, ".strtab") == 0) strtab = &sh[i];
    }
    if (auto a = scan(dynsym, dynstr)) return a;
    return scan(symtab, strtab);
}

static struct link_map* link_map_from_dt_debug() {
    struct Ctx {
        struct link_map* lm;
    } ctx{nullptr};
    dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) -> int {
        auto* ctx = (Ctx*)data;
        if (!info->dlpi_phdr) return 0;
        for (ElfW(Half) i = 0; i < info->dlpi_phnum; i++) {
            const ElfW(Phdr)* ph = &info->dlpi_phdr[i];
            if (ph->p_type != PT_DYNAMIC) continue;
            auto* dyn = (ElfW(Dyn)*)(info->dlpi_addr + ph->p_vaddr);
            for (int k = 0; k < 512 && dyn[k].d_tag != DT_NULL; k++) {
                if (dyn[k].d_tag == DT_DEBUG && dyn[k].d_un.d_ptr) {
                    auto* dbg = (struct r_debug*)dyn[k].d_un.d_ptr;
                    if (dbg && dbg->r_map) {
                        ctx->lm = dbg->r_map;
                        return 1;
                    }
                }
            }
        }
        return 0;
    }, &ctx);
    if (ctx.lm) return ctx.lm;
    void* sym = dlsym(RTLD_DEFAULT, "_r_debug");
    if (sym) {
        auto* dbg = (struct r_debug*)sym;
        if (dbg) return dbg->r_map;
    }
    return nullptr;
}

Probe probe_solist() {
    Probe p;
    std::string linker_path = module_path_from_maps("/linker64");
    if (linker_path.empty()) linker_path = module_path_from_maps("/linker");
    uintptr_t lbase = linker_load_base("/linker64");
    if (!lbase) lbase = linker_load_base("/linker");
    int phdr_n = 0;
    dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) -> int {
        int* n = (int*)data;
        (*n)++;
        return 0;
    }, &phdr_n);
    int maps_so = 0;
    for (auto& e : parse_maps()) {
        if (strchr(e.perms, 'x') && e.path.find(".so") != std::string::npos) maps_so++;
    }
    int walk = 0;
    int r_walk = 0;
    std::string names;
    bool found_hidden = false;
    if (!linker_path.empty() && lbase) {
        const char* want[] = {"__dl__ZL6solist", "_ZL6solist", "solist", nullptr};
        const char* want_main[] = {"__dl__ZL6somain", "_ZL6somain", "somain", nullptr};
        const char* want_pre[] = {"__dl__ZL13g_ld_preloads", "_ZL13g_ld_preloads", nullptr};
        uintptr_t solist_ptr = 0, somain_ptr = 0, preloads = 0;
        for (int i = 0; want[i] && !solist_ptr; i++)
            solist_ptr = elf_lookup(linker_path.c_str(), lbase, want[i]);
        for (int i = 0; want_main[i] && !somain_ptr; i++)
            somain_ptr = elf_lookup(linker_path.c_str(), lbase, want_main[i]);
        for (int i = 0; want_pre[i] && !preloads; i++)
            preloads = elf_lookup(linker_path.c_str(), lbase, want_pre[i]);
        char buf[256];
        snprintf(buf, sizeof(buf), "solist_sym=%p somain_sym=%p g_ld_preloads=%p linker=%s",
                 (void*)solist_ptr, (void*)somain_ptr, (void*)preloads,
                 linker_path.empty() ? "-" : linker_path.c_str());
        names = buf;
        if (solist_ptr) {
            auto maps = parse_maps();
            if (!ptr_readable(maps, (const void*)solist_ptr)) {
                names += " solist_ptr unreadable";
            } else {
            void* head = *(void**)solist_ptr;
            void* somain = (somain_ptr && ptr_readable(maps, (const void*)somain_ptr)) ? *(void**)somain_ptr
                                                                                        : nullptr;
            size_t next_off = 0x30;
            if (head && somain && ptr_readable(maps, head, 128 * sizeof(void*))) {
                for (size_t i = 0; i < 128; i++) {
                    void* maybe = nullptr;
                    memcpy(&maybe, (char*)head + i * sizeof(void*), sizeof(maybe));
                    if (maybe == somain) {
                        next_off = i * sizeof(void*);
                        break;
                    }
                }
            }
            void* cur = head;
            bool walk_ended = false;
            for (int step = 0; cur && step < 1024; step++) {
                if (!ptr_readable(maps, cur, next_off + sizeof(void*))) break;
                walk++;
                void* nxt = nullptr;
                memcpy(&nxt, (void*)((uintptr_t)cur + next_off), sizeof(nxt));
                if (!nxt || nxt == head || nxt == cur) {
                    walk_ended = true;
                    break;
                }
                if (!ptr_readable(maps, nxt)) break;
                cur = nxt;
            }
            names += " soinfo_walk=" + std::to_string(walk);
            names += " next_off=" + std::to_string(next_off);
            names += walk_ended ? " walk_ended" : " walk_truncated";
            // Truncated walks (unreadable soinfo) are not proof of a hidden module.
            if (walk_ended && walk > 0 && maps_so > walk + 16) found_hidden = true;
            }
        }
        if (preloads) names += " preloads_addr_ok";
    }
    struct link_map* lm = link_map_from_dt_debug();
    {
        auto maps = parse_maps();
        for (struct link_map* m = lm; m && r_walk < 1024; m = m->l_next) {
            if (!ptr_readable(maps, m, sizeof(void*) * 4)) break;
            r_walk++;
        }
    }
    names += " r_map_walk=" + std::to_string(r_walk);
    if (walk == 0 && r_walk > 0) walk = r_walk;
    const char* ld = getenv("LD_PRELOAD");
    if (ld && *ld) {
        p.hit = true;
        names += std::string(" LD_PRELOAD=") + ld;
    }
    if (found_hidden) p.hit = true;
    p.detail = "dl_iterate_phdr=" + std::to_string(phdr_n) + " maps_so_x=" + std::to_string(maps_so) +
               " walk=" + std::to_string(walk) + " " + names;
    return p;
}

static bool covering_mount(const std::string& path, const std::string& mi, unsigned* maj, unsigned* minv) {
    unsigned best = 0, bm = 0, bn = 0;
    const char* sp = mi.c_str();
    while (*sp) {
        const char* nl = strchr(sp, '\n');
        std::string line(sp, nl ? (size_t)(nl - sp) : strlen(sp));
        unsigned m = 0, n = 0;
        if (sscanf(line.c_str(), "%*d %*d %u:%u", &m, &n) < 2) {
            if (!nl) break;
            sp = nl + 1;
            continue;
        }
        int field = 0;
        std::string mp;
        const char* p = line.c_str();
        while (*p) {
            while (*p == ' ') p++;
            const char* s = p;
            while (*p && *p != ' ') p++;
            if (field == 4) {
                mp.assign(s, (size_t)(p - s));
                break;
            }
            field++;
            if (*p) p++;
        }
        if (!mp.empty()) {
            bool match = path == mp || (path.size() > mp.size() && path.compare(0, mp.size(), mp) == 0 &&
                                        (mp == "/" || path[mp.size()] == '/'));
            if (match && mp.size() >= best) {
                best = (unsigned)mp.size();
                bm = m;
                bn = n;
            }
        }
        if (!nl) break;
        sp = nl + 1;
    }
    if (best == 0) return false;
    *maj = bm;
    *minv = bn;
    return true;
}

struct MountAnchor {
    unsigned id = 0, maj = 0, minv = 0;
    char fs[16] = {};
    bool ok = false;
};

static MountAnchor covering_anchor(const char* path, const std::string& mi) {
    MountAnchor a;
    unsigned best = 0;
    const char* sp = mi.c_str();
    while (*sp) {
        const char* nl = strchr(sp, '\n');
        std::string line(sp, nl ? (size_t)(nl - sp) : strlen(sp));
        unsigned id = 0, m = 0, n = 0;
        if (sscanf(line.c_str(), "%u %*d %u:%u", &id, &m, &n) < 3) {
            if (!nl) break;
            sp = nl + 1;
            continue;
        }
        int field = 0;
        std::string mp;
        const char* p = line.c_str();
        while (*p) {
            while (*p == ' ') p++;
            const char* s = p;
            while (*p && *p != ' ') p++;
            if (field == 4) {
                mp.assign(s, (size_t)(p - s));
                break;
            }
            field++;
            if (*p) p++;
        }
        if (!mp.empty()) {
            size_t plen = strlen(path);
            bool match = mp == path || (plen > mp.size() && strncmp(path, mp.c_str(), mp.size()) == 0 &&
                                        (mp == "/" || path[mp.size()] == '/'));
            if (match && mp.size() >= best) {
                best = (unsigned)mp.size();
                a.id = id;
                a.maj = m;
                a.minv = n;
                a.ok = true;
                auto dash = line.find(" - ");
                if (dash != std::string::npos) {
                    sscanf(line.c_str() + dash + 3, "%15s", a.fs);
                }
            }
        }
        if (!nl) break;
        sp = nl + 1;
    }
    return a;
}

std::string mount_ns_pack() {
    auto mi = read_file("/proc/self/mountinfo", 1 << 18);
    char ns[96] = {};
    ssize_t nr = readlink("/proc/self/ns/mnt", ns, sizeof(ns) - 1);
    if (nr > 0) ns[nr] = 0;
    auto apex = covering_anchor("/apex", mi);
    auto sys = covering_anchor("/system", mi);
    auto vend = covering_anchor("/vendor", mi);
    char buf[384];
    snprintf(buf, sizeof(buf),
             "ns=%s apex=%u|%u:%u|%s system=%u|%u:%u|%s vendor=%u|%u:%u|%s",
             ns[0] ? ns : "-", apex.id, apex.maj, apex.minv, apex.ok ? (apex.fs[0] ? apex.fs : "?") : "none",
             sys.id, sys.maj, sys.minv, sys.ok ? (sys.fs[0] ? sys.fs : "?") : "none", vend.id, vend.maj, vend.minv,
             vend.ok ? (vend.fs[0] ? vend.fs : "?") : "none");
    return buf;
}

static bool parse_anchor_dev(const std::string& pack, const char* key, unsigned* maj, unsigned* minv) {
    auto pos = pack.find(key);
    if (pos == std::string::npos) return false;
    unsigned id = 0, m = 0, n = 0;
    if (sscanf(pack.c_str() + pos + strlen(key), "%u|%u:%u", &id, &m, &n) < 3) return false;
    *maj = m;
    *minv = n;
    return true;
}

Probe probe_mount_ns() {
    Probe p;
    std::string main = mount_ns_pack();
    const auto& iso = isolate_snap();
    std::string d = "main=";
    d += main;
    d += "\nisolated=";
    auto ip = iso.find("ns=");
    d += (ip == std::string::npos) ? iso.substr(0, 180) : iso.substr(ip, 240);
    d += '\n';
    if (iso.empty() || iso.find("timeout") != std::string::npos || iso.find("bind_fail") != std::string::npos) {
        p.detail = d + "Mount Namespace Drift Unavailable";
        return p;
    }
    bool drift = false;
    for (auto* k : {"apex=", "system=", "vendor="}) {
        unsigned mm = 0, mn = 0, im = 0, in = 0;
        bool a = parse_anchor_dev(main, k, &mm, &mn);
        bool b = parse_anchor_dev(iso, k, &im, &in);
        if (a && b && (mm != im || mn != in)) {
            drift = true;
            d += k;
            d += " main=";
            d += std::to_string(mm) + ":" + std::to_string(mn);
            d += " isolated=";
            d += std::to_string(im) + ":" + std::to_string(in);
            d += '\n';
        }
    }
    p.hit = drift;
    if (p.hit) d += "Main process and isolated process have different mount anchors.\nMount Namespace Anchor Drift";
    else d += "Mount Namespace Drift Clean";
    p.detail = d;
    return p;
}

Probe probe_sandbox_stat() {
    Probe p;
    auto cmd = read_file("/proc/self/cmdline", 256);
    std::string pkg = cmd.empty() ? std::string() : std::string(cmd.c_str());
    std::vector<std::string> paths;
    if (!pkg.empty() && pkg.find('/') == std::string::npos && pkg.find(':') == std::string::npos) {
        paths.push_back("/data/user/0/" + pkg);
        paths.push_back("/data/data/" + pkg);
    }
    auto mi = read_file("/proc/self/mountinfo");
    std::string d;
    int mismatch = 0;
    for (auto& path : paths) {
        struct stat st {};
        if (stat(path.c_str(), &st) != 0) continue;
        unsigned sm = major(st.st_dev), sn = minor(st.st_dev);
        unsigned mm = 0, mn = 0;
        bool cov = covering_mount(path, mi, &mm, &mn);
        char line[192];
        snprintf(line, sizeof(line), "%s stat=%u:%u mountinfo=%s%u:%u", path.c_str(), sm, sn, cov ? "" : "none/", mm,
                 mn);
        d += line;
        d += '\n';
        if (!mi.empty() && (!cov || sm != mm || sn != mn)) {
            mismatch++;
            d += "STAT/MOUNT INCONSISTENCY: app sandbox dir stat disagrees with mountinfo (spoof/redirect)\n";
        }
    }
    p.hit = mismatch > 0;
    p.detail = d.empty() ? "stat failed" : d;
    return p;
}

Probe probe_bind_mount() {
    Probe p;
    auto mi = read_file("/proc/self/mountinfo");
    bool rootish = blob_has_ci(mi.c_str(), "magisk") || blob_has_ci(mi.c_str(), "/data/adb") ||
                   blob_has_ci(mi.c_str(), "kernelsu") || blob_has_ci(mi.c_str(), "debug_ramdisk");
    if (rootish && (mi.find("bind") != std::string::npos || mi.find("overlay") != std::string::npos)) {
        p.hit = true;
        p.detail = "root-related bind/overlay in mountinfo";
    } else {
        p.detail = "no magisk/ksu bind";
    }
    return p;
}

Probe probe_resetprop() {
    Probe p;
    std::string fp = prop("ro.build.fingerprint");
    std::string tags = prop("ro.build.tags");
    std::string deb = prop("ro.debuggable");
    std::string secure = prop("ro.secure");
    std::string warr = prop("ro.vendor.warranty_bit");
    auto load_prop_file = [](const char* path) {
        std::string via_libc = read_file(path, 64 * 1024);
        if (!via_libc.empty()) return via_libc;
        long fd = svc5(SYS_openat, AT_FDCWD, (long)path, O_RDONLY | O_CLOEXEC, 0, 0);
        if (fd < 0 || fd > 1e6) return std::string();
        char buf[4096];
        std::string s;
        for (;;) {
            long n = read((int)fd, buf, sizeof(buf));
            if (n <= 0) break;
            s.append(buf, (size_t)n);
            if (s.size() > 64 * 1024) break;
        }
        close((int)fd);
        return s;
    };
    std::string bp = load_prop_file("/system/build.prop");
    if (bp.empty()) bp = load_prop_file("/vendor/build.prop");
    auto grab = [&](const char* key) {
        std::string k = std::string(key) + "=";
        auto pos = bp.find(k);
        if (pos == std::string::npos) return std::string();
        auto end = bp.find('\n', pos);
        return bp.substr(pos + k.size(), end - pos - k.size());
    };
    std::string file_fp = grab("ro.build.fingerprint");
    std::string file_tags = grab("ro.build.tags");
    if (!file_fp.empty() && !fp.empty() && file_fp != fp) {
        p.hit = true;
        p.detail += "fingerprint getprop!=build.prop\n";
    }
    if (!file_tags.empty() && !tags.empty() && file_tags != tags) {
        p.hit = true;
        p.detail += "tags mismatch\n";
    }
    // Per-app property spoof often rewrites ro.build.fingerprint but leaves
    // ro.system / ro.vendor / ro.bootimage fingerprints on the real ROM.
    auto sysfp = prop("ro.system.build.fingerprint");
    auto venfp = prop("ro.vendor.build.fingerprint");
    auto bootfp = prop("ro.bootimage.build.fingerprint");
    // OEM HyperOS/One UI 的 product/system/vendor fingerprint 本来就不相同
    // （例如 Redmi/zorn vs Xiaomi/missi，vendor 还是旧基线），不能当 resetprop。
    // 只保留 detail，真正的篡改由 build.prop 对比、ro.debuggable/secure、
    // warranty_bit 和属性区 serial 判定。
    if (!fp.empty()) {
        if (!sysfp.empty() && sysfp != fp) p.detail += "note: system fp differs (OEM build split)\n";
        if (!venfp.empty() && venfp != fp) p.detail += "note: vendor fp differs (OEM build split)\n";
        if (!bootfp.empty() && bootfp != fp) p.detail += "note: bootimage fp differs\n";
    }
    if (deb == "1") {
        p.hit = true;
        p.detail += "find ro.debuggable == 1\n";
    }
    if (secure == "0") {
        p.hit = true;
        p.detail += "find ro.secure == 0\n";
    }
    if (!warr.empty() && warr != "0") {
        p.hit = true;
        p.detail += "ro.vendor.warranty_bit=";
        p.detail += warr;
        p.detail += '\n';
    }
    if (prop("ro.boot.vbmeta.digest").empty() && !prop("ro.boot.verifiedbootstate").empty()) {
        p.detail += "vbmeta.digest empty\n";
    }
    p.detail += "fp_prop=" + fp.substr(0, 80) + "\nfp_file=" + file_fp.substr(0, 80) +
                "\nsys_fp=" + sysfp.substr(0, 80) + "\nven_fp=" + venfp.substr(0, 60);
    if (p.hit) p.detail += "\nFind Prop Modify Mark";
    return p;
}

Probe probe_build_identity() {
    Probe p;
    auto fp = prop("ro.build.fingerprint");
    auto tags = prop("ro.build.tags");
    auto type = prop("ro.build.type");
    auto date = prop("ro.build.date");
    auto date_utc = prop("ro.build.date.utc");
    auto brand = prop("ro.product.brand");
    auto model = prop("ro.product.model");
    auto ver = read_file("/proc/version");
    struct utsname u {};
    uname(&u);
    struct utsname ur {};
    long urc = svc5(SYS_uname, (long)&ur, 0, 0, 0, 0);
    bool raw_ok = !(urc < 0 && urc >= -4095);
    bool dirty = ver.find("dirty") != std::string::npos || ver.find("maybe-dirty") != std::string::npos ||
                 strstr(u.release, "dirty") || strstr(u.release, "maybe-dirty") ||
                 (raw_ok && (strstr(ur.release, "dirty") || strstr(ur.release, "maybe-dirty")));
    bool epoch = ver.find("1970") != std::string::npos || date.find("1970") != std::string::npos || date_utc == "0" ||
                 strstr(u.version, "1970") || (raw_ok && strstr(ur.version, "1970"));
    bool toybox = ver.find("Toybox") != std::string::npos || strstr(u.version, "Toybox") ||
                  (raw_ok && strstr(ur.version, "Toybox"));
    bool release = fp.find("release-keys") != std::string::npos || tags.find("release-keys") != std::string::npos;
    bool user = type == "user";
    // OEM GKI kernels often carry a "-dirty" localversion. That is not a
    // fingerprint spoof. Toybox/1970 epoch are the redroid/container tells.
    p.hit = (release && user && (epoch || toybox));
    p.detail = "fingerprint=" + fp + "\ntags=" + tags + " type=" + type + "\nproc_version dirty=" +
               (dirty ? "1" : "0") + " epoch1970=" + (epoch ? "1" : "0") + " toybox=" + (toybox ? "1" : "0") +
               "\nkernel=" + std::string(u.release) + " " + std::string(u.version).substr(0, 80) +
               "\nrawuname=" + (raw_ok ? std::string(ur.release) + " " + std::string(ur.version).substr(0, 60)
                                       : std::string("na"));
    if (p.hit) p.detail += "\nBuild Identity Source Mismatch";
    return p;
}

static double read_uptime_sec() {
    const double kMax = 10.0 * 365 * 24 * 3600;
    struct timespec bt {};
    if (clock_gettime(CLOCK_BOOTTIME, &bt) == 0) {
        double u = (double)bt.tv_sec + (double)bt.tv_nsec / 1e9;
        if (u >= 0 && u < kMax) return u;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &bt) == 0) {
        double u = (double)bt.tv_sec + (double)bt.tv_nsec / 1e9;
        if (u >= 0 && u < kMax) return u;
    }
    struct sysinfo si {};
    if (sysinfo(&si) == 0 && si.uptime > 0 && (double)si.uptime < kMax)
        return (double)si.uptime;
    auto up = read_file("/proc/uptime", 128);
    double u = -1;
    if (sscanf(up.c_str(), "%lf", &u) == 1 && u >= 0 && u < kMax) return u;
    return -1;
}

Probe probe_boot_time() {
    Probe p;
    auto stat = read_file("/proc/stat", 4096);
    int64_t btime = 0;
    auto pos = stat.find("btime ");
    if (pos != std::string::npos) btime = (int64_t)strtoll(stat.c_str() + pos + 6, nullptr, 10);
    double uptime = read_uptime_sec();
    struct timespec ts {};
    int64_t now = 0;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) now = (int64_t)ts.tv_sec;
    const double kMaxUptime = 10.0 * 365 * 24 * 3600;
    bool clocks_ok = uptime >= 0 && uptime < kMaxUptime && now > 100000000 && now < 4000000000LL;
    int64_t derived = 0, delta = -1;
    if (clocks_ok) {
        derived = now - (int64_t)(uptime + 0.5);
        if (btime > 100000) delta = derived >= btime ? derived - btime : btime - derived;
    }
    std::string first = prop("ro.runtime.firstboot");
    // Overflow / unreadable clocks are not a spoof hit. A sane multi-hour
    // realtime-uptime vs btime gap is the actual "boot time modify" signal.
    p.hit = clocks_ok && btime > 100000 && delta > 3600;
    char buf[256];
    snprintf(buf, sizeof(buf),
             "btime=%lld now=%lld uptime=%.0f derived=%lld delta=%lld firstboot=%s",
             (long long)btime, (long long)now, uptime, (long long)derived, (long long)delta,
             first.c_str());
    p.detail = buf;
    return p;
}

Probe probe_apexd_boot() {
    Probe p;
    auto boot = prop("ro.boottime.apexd");
    auto zyg = prop("ro.boottime.zygote");
    auto svc = prop("init.svc.apexd");
    auto dap = prop("Dapexd.status");
    auto upd = prop("ro.apex.updatable");
    // packed DEX: ro.boottime.apexd → Apexd boot time.
    // Some devices do not export ro.boottime.apexd.
    // Spoofed redroid exports a huge ns value. Non-empty is the hit.
    p.hit = !boot.empty() || !dap.empty();
    char buf[384];
    snprintf(buf, sizeof(buf),
             "%s init.svc.apexd=%s zygote=%s Dapexd.status=%s updatable=%s",
             boot.empty() ? "ro.boottime.apexd=" : boot.c_str(), svc.c_str(), zyg.c_str(),
             dap.empty() ? "-" : dap.c_str(), upd.c_str());
    p.detail = buf;
    if (p.hit) p.detail += "\nFind Apexd Boot Time";
    else p.detail += "\nno apexd boottime";
    return p;
}

Probe probe_ptrace_nspid() {
    Probe p;
    auto st = read_file("/proc/self/status");
    pid_t pid = getpid(), ppid = getppid();
    int nspid = -1, nsppid = -1;
    auto np = st.find("NSpid:");
    if (np != std::string::npos) nspid = atoi(st.c_str() + np + 6);
    auto npp = st.find("PPid:");
    if (npp != std::string::npos) nsppid = atoi(st.c_str() + npp + 5);
    uid_t uid = getuid();
    int suid = -1;
    auto us = st.find("Uid:");
    if (us != std::string::npos) suid = atoi(st.c_str() + us + 4);
    p.hit = (nspid > 0 && nspid != pid) || (nsppid >= 0 && nsppid != ppid) || (suid >= 0 && (uid_t)suid != uid);
    char buf[192];
    snprintf(buf, sizeof(buf), "pid=%d NSpid=%d ppid=%d status_PPid=%d uid=%d status_Uid=%d",
             pid, nspid, ppid, nsppid, uid, suid);
    p.detail = buf;
    return p;
}

Probe probe_seccomp() {
    Probe p;
    int sc = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    long sc_raw = svc5(SYS_prctl, PR_GET_SECCOMP, 0, 0, 0, 0);
    auto st = read_file("/proc/self/status");
    int status_sc = -1;
    auto pos = st.find("Seccomp:");
    if (pos != std::string::npos) status_sc = atoi(st.c_str() + pos + 8);
    // Android 8+ app processes normally have filter mode 2. Missing line or mode 0 is unidbg/hook.
    p.hit = sc < 0 || sc == 0 || status_sc == 0 || sc_raw == 0;
    char buf[160];
    snprintf(buf, sizeof(buf), "PR_GET_SECCOMP=%d raw=%ld status_Seccomp=%d", sc, sc_raw, status_sc);
    p.detail = buf;
    return p;
}

static bool g_attest_set = false;
static bool g_tee_fail = false, g_aosp = false, g_keybox = false;
static std::string g_attest_detail;

void set_attest_jni_result(bool tee_fail, bool aosp_software, bool keybox, const std::string& detail) {
    g_attest_set = true;
    g_tee_fail = tee_fail;
    g_aosp = aosp_software;
    g_keybox = keybox;
    g_attest_detail = detail;
}

Probe probe_attestation() {
    Probe p;
    bool tee_dev = exists_path("/dev/tee0") || exists_path("/dev/teepriv0") ||
                   exists_path("/vendor/lib64/hw/android.hardware.gatekeeper") ||
                   exists_path("/system/lib64/hw/keystore.default.so");
    auto ks = prop("ro.hardware.keystore");
    auto km = prop("ro.hardware.keystore_deserde");
    p.hit = g_attest_set ? g_tee_fail : (!tee_dev && ks.find("software") != std::string::npos);
    p.detail = "tee_dev=" + std::string(tee_dev ? "1" : "0") + " keystore=" + ks + " " + km;
    if (g_attest_set) {
        p.hit = g_tee_fail;
        p.detail += "\njni=" + g_attest_detail;
    }
    return p;
}

Probe probe_aosp_key() {
    Probe p;
    if (g_attest_set) {
        p.hit = g_aosp;
        p.detail = g_attest_detail.empty() ? "aosp_software=jni" : g_attest_detail;
        return p;
    }
    auto ks = prop("ro.hardware.keystore");
    p.hit = ks.find("software") != std::string::npos || exists_path("/system/lib64/libkeystore-engine.so") &&
                                                                !exists_path("/vendor/lib64/hw/android.hardware.keymaster");
    p.detail = "keystore=" + ks + " (no JNI chain yet)";
    return p;
}

Probe probe_keybox() {
    Probe p;
    if (g_attest_set) {
        p.hit = g_keybox;
        p.detail = g_attest_detail;
        return p;
    }
    p.detail = "keybox not evaluated until JNI attestation";
    return p;
}

Probe probe_isolate_diff() {
    Probe p;
    auto main = iso_snapshot();
    const auto& iso = isolate_snap();
    std::string d;
    d += "main ";
    d += main;
    d += "\nisolate ";
    d += iso;
    d += '\n';
    bool iso_ok = !iso.empty() && iso.find("timeout") == std::string::npos &&
                  iso.find("bind_fail") == std::string::npos && iso.find("err=") == std::string::npos;
    int field_div = 0;
    const char* keys[] = {"su",
                          "mag",
                          "ksu",
                          "mods",
                          "shamiko",
                          "adb_ents",
                          "adb_denied",
                          "maps_magisk",
                          "maps_ksu",
                          "maps_lsp",
                          "ksu_cookie",
                          "ksu_umount",
                          "ksu_ver",
                          nullptr};
    if (iso_ok) {
        for (int i = 0; keys[i]; i++) {
            int a = snap_field(main, keys[i]);
            int b = snap_field(iso, keys[i]);
            if (a == -999 || b == -999 || a == b) continue;
            field_div++;
            d += keys[i];
            d += " main=";
            d += std::to_string(a);
            d += " iso=";
            d += std::to_string(b);
            d += '\n';
        }
        int main_svc = snap_field(main, "adb_svc");
        int iso_svc = snap_field(iso, "adb_svc");
        if (main_svc != -999 && iso_svc != -999 && main_svc != iso_svc) {
            field_div++;
            d += "adb_svc main=" + std::to_string(main_svc) + " iso=" + std::to_string(iso_svc) + "\n";
        }
        auto name_of = [](const std::string& s) {
            auto pos = s.find("adb_n=");
            if (pos == std::string::npos) return std::string();
            auto end = s.find(' ', pos);
            return s.substr(pos + 6, end == std::string::npos ? std::string::npos : end - pos - 6);
        };
        auto mn = name_of(main), in = name_of(iso);
        if (!mn.empty() && !in.empty() && mn != in) {
            field_div++;
            d += "adb_n main=" + mn + " iso=" + in + "\n";
        }
    }
    const char* paths[] = {"/data/adb", "/data/adb/magisk", "/data/adb/ksu", "/system/bin/su",
                           "/debug_ramdisk/.magisk", nullptr};
    int hook_div = 0;
    for (int i = 0; paths[i]; i++) {
        auto o = observe_path(paths[i]);
        if (obs_diverge(o)) {
            hook_div++;
            d += paths[i];
            d += " libc=" + std::to_string(o.libc_rc) + "/" + std::to_string(o.libc_err) +
                 " svc=" + std::to_string(o.svc_rc) + "/" + std::to_string(o.svc_err) + "\n";
        }
    }
    p.hit = field_div > 0 || hook_div > 0;
    p.detail = "iso_field_diverge=" + std::to_string(field_div) + " libc_svc=" + std::to_string(hook_div) +
               "\n" + d;
    return p;
}

Probe probe_zygisk_assistant() {
    static const char* xs[] = {"/data/adb/modules/zygisk_assistant", "/data/adb/modules/zygisk-assistant",
                               "/data/adb/modules/Zygisk-Assistant", nullptr};
    Probe p;
    for (int i = 0; xs[i]; i++)
        if (path_visible(xs[i])) {
            p.hit = true;
            p.detail += xs[i];
            p.detail += '\n';
        }
    auto mods = modules_matching("zygisk-assistant");
    if (mods.empty()) mods = modules_matching("zygisk_assistant");
    if (!mods.empty()) {
        p.hit = true;
        p.detail += mods;
        p.detail += '\n';
    }
    auto maps = read_file("/proc/self/maps");
    if (blob_has_ci(maps.c_str(), "zygisk_assistant") || blob_has_ci(maps.c_str(), "zygisk-assistant")) {
        p.hit = true;
        p.detail += "maps zygisk-assistant\n";
    }
    if (!p.hit) p.detail = "no zygisk-assistant";
    return p;
}

Probe probe_peekaboo() {
    static const char* xs[] = {"/data/adb/kpm/cherish_peekaboo.kpm", "/data/adb/kpm/cherish_peekaboo",
                               "/data/adb/modules/cherish_peekaboo", "/data/adb/ksu/modules/peekaboo",
                               nullptr};
    Probe p;
    for (int i = 0; xs[i]; i++)
        if (path_visible(xs[i])) {
            p.hit = true;
            p.detail += xs[i];
            p.detail += '\n';
        }
    auto mods = modules_matching("peekaboo");
    if (!mods.empty()) {
        p.hit = true;
        p.detail += mods;
        p.detail += '\n';
    }
    auto maps = read_file("/proc/self/maps");
    if (blob_has_ci(maps.c_str(), "peekaboo") || blob_has_ci(maps.c_str(), "cherish_peekaboo")) {
        p.hit = true;
        p.detail += "maps peekaboo\n";
    }
    if (!p.hit) p.detail = "no peekaboo KPM";
    return p;
}

Probe probe_umount_detach() {
    Probe p;
    static const char* xs[] = {"/data/adb/modules/zygisk-detach", "/data/adb/modules/zygisk_detach",
                               "/data/adb/modules/ksu_susfs", nullptr};
    for (int i = 0; xs[i]; i++)
        if (path_visible(xs[i])) {
            p.hit = true;
            p.detail += xs[i];
            p.detail += '\n';
        }
    auto mods = modules_matching("zygisk-detach");
    if (mods.empty()) mods = modules_matching("susfs");
    if (!mods.empty()) {
        p.hit = true;
        p.detail += mods;
        p.detail += '\n';
    }
    auto mi = read_file("/proc/self/mountinfo");
    if (blob_has_ci(mi.c_str(), "zygisk-detach") || blob_has_ci(mi.c_str(), "ksu_susfs")) {
        p.hit = true;
        p.detail += "mountinfo detach/susfs\n";
    }
    auto main = iso_snapshot();
    if (snap_field(main, "ksu_umount") == 1) {
        p.hit = true;
        p.detail += "ksu uid_should_umount=1\n";
    }
    const auto& iso = isolate_snap();
    if (!iso.empty() && iso.find("timeout") == std::string::npos) {
        int iso_adb = snap_field(iso, "adb_svc");
        int main_adb = snap_field(main, "adb_svc");
        if (iso_adb == 0 && main_adb != 0 && iso_adb != -999 && main_adb != -999) {
            p.hit = true;
            p.detail += "isolate /data/adb visible, main unmounted\n";
        }
    }
    if (!p.hit) p.detail = "no umount/zygisk-detach";
    return p;
}

Probe probe_dex2oat_mount() {
    Probe p;
    auto mi = read_file("/proc/self/mountinfo");
    auto maps = read_file("/proc/self/maps");
    if (mi.find("dex2oat") != std::string::npos || mi.find("lspd") != std::string::npos) {
        p.hit = true;
        p.detail += "mountinfo dex2oat/lspd\n";
    }
    if (maps.find("lspd") != std::string::npos && maps.find("dex2oat") != std::string::npos) {
        p.hit = true;
        p.detail += "maps lspd+dex2oat\n";
    }
    if (exists_path("/data/adb/lspd/dex2oat")) {
        p.hit = true;
        p.detail += "/data/adb/lspd/dex2oat\n";
    }
    if (!p.hit) p.detail = "no lspd dex2oat mount";
    return p;
}

Probe probe_art_method() {
    Probe p;
    unsigned long b = 0;
    auto maps = parse_maps();
    for (auto& e : maps) {
        if (e.path.find("libart.so") != std::string::npos && strchr(e.perms, 'x')) {
            b = e.start;
            break;
        }
    }
    p.hit = b == 0;
    p.detail = b ? ("libart x-base=" + std::to_string(b) + " (check_jvm_method walks ArtMethod*)")
                 : "libart.so not mapped";
    return p;
}

extern "C" void __system_property_read_callback(const prop_info* pi,
                                                void (*callback)(void* cookie, const char* name, const char* value,
                                                                 uint32_t serial),
                                                void* cookie) __attribute__((weak));

struct PropSer {
    uint32_t serial = 0;
    char val[92] = {};
    bool ok = false;
};

static void prop_ser_cb(void* cookie, const char* /*name*/, const char* value, uint32_t serial) {
    auto* s = (PropSer*)cookie;
    s->serial = serial;
    s->ok = true;
    if (value) {
        size_t n = strlen(value);
        if (n > 91) n = 91;
        memcpy(s->val, value, n);
        s->val[n] = 0;
    }
}

static bool read_prop_serial(const char* key, PropSer* out) {
    if (!key || !out || !__system_property_read_callback) return false;
    const prop_info* pi = __system_property_find(key);
    if (!pi) return false;
    __system_property_read_callback(pi, prop_ser_cb, out);
    return out->ok;
}

Probe probe_prop_serial() {
    Probe p;
    static const char* keys[] = {"ro.boot.flash.locked", "ro.boot.vbmeta.device_state",
                                 "ro.boot.verifiedbootstate", "vendor.boot.vbmeta.device_state",
                                 "vendor.boot.verifiedbootstate", "ro.build.fingerprint",
                                 "ro.build.tags", "ro.debuggable", nullptr};
    std::string d;
    for (int i = 0; keys[i]; i++) {
        PropSer s;
        if (!read_prop_serial(keys[i], &s)) {
            d += keys[i];
            d += " unreadable\n";
            continue;
        }
        uint32_t pi_serial = s.serial;
        const prop_info* pi = __system_property_find(keys[i]);
        if (pi) memcpy(&pi_serial, pi, 4);
        char line[200];
        snprintf(line, sizeof(line), "%s serial=0x%x pi=0x%x slen=%u val=%s\n", keys[i], s.serial, pi_serial,
                 s.serial >> 24, s.val);
        d += line;
        if (prop_serial_abnormal(s.serial, s.val) || prop_serial_abnormal(pi_serial, s.val) ||
            pi_serial != s.serial) {
            p.hit = true;
            d += "Abnormal prop serial for: ";
            d += keys[i];
            d += '\n';
        }
    }

    DIR* dir = opendir("/dev/__properties__");
    if (!dir) {
        d += "/dev/__properties__ unreadable errno=";
        d += std::to_string(errno);
        d += '\n';
    } else {
        int areas = 0, holes = 0, remains = 0, active = 0;
        while (dirent* de = readdir(dir)) {
            if (de->d_name[0] == '.') continue;
            char path[320];
            snprintf(path, sizeof(path), "/dev/__properties__/%s", de->d_name);
            struct stat st {};
            if (stat(path, &st) != 0) continue;
            if (st.st_mode & 0222) {
                p.hit = true;
                d += "Abnormal permission for prop area: ";
                d += de->d_name;
                char mbuf[32];
                snprintf(mbuf, sizeof(mbuf), " mode=0%o\n", (unsigned)(st.st_mode & 0777));
                d += mbuf;
            }
            if (!S_ISREG(st.st_mode) || st.st_size < 128 || st.st_size > (off_t)(2u << 20)) continue;
            int fd = open(path, O_RDONLY | O_CLOEXEC);
            if (fd < 0) continue;
            size_t sz = (size_t)st.st_size;
            void* mm = mmap(nullptr, sz, PROT_READ, MAP_SHARED, fd, 0);
            close(fd);
            if (mm == MAP_FAILED) continue;
            PropAreaWalk w;
            walk_prop_area((const uint8_t*)mm, sz, &w);
            if (w.valid) {
                areas++;
                active += w.active;
                if (w.hole) {
                    holes++;
                    p.hit = true;
                    d += "Found hole in prop area: ";
                    d += de->d_name;
                    d += '\n';
                }
                if (w.remains) {
                    remains++;
                    p.hit = true;
                    d += "Abnormal prop remains for: ";
                    d += de->d_name;
                    d += '\n';
                }
                for (int i = 0; keys[i]; i++) {
                    uint32_t raw = 0;
                    char val[92] = {};
                    if (!prop_area_lookup((const uint8_t*)mm, sz, keys[i], &raw, val, sizeof(val))) continue;
                    PropSer s;
                    bool cb = read_prop_serial(keys[i], &s);
                    if (prop_serial_abnormal(raw, val)) {
                        p.hit = true;
                        d += "Abnormal prop serial for: ";
                        d += keys[i];
                        d += " (mmap)\n";
                    }
                    if (cb && (raw != s.serial || strcmp(val, s.val) != 0)) {
                        p.hit = true;
                        d += "Abnormal prop serial for: ";
                        d += keys[i];
                        char x[160];
                        snprintf(x, sizeof(x), " mmap=0x%x val=%s cb=0x%x val=%s\n", raw, val, s.serial, s.val);
                        d += x;
                    }
                }
            }
            munmap(mm, sz);
        }
        closedir(dir);
        d += "activeEntries=";
        d += std::to_string(active);
        d += " areas=";
        d += std::to_string(areas);
        d += " holes=";
        d += std::to_string(holes);
        d += " remains=";
        d += std::to_string(remains);
        d += '\n';
    }

    auto rp = probe_resetprop();
    if (rp.hit) {
        p.hit = true;
        d += rp.detail;
        d += '\n';
    }
    static const char* gpkeys[] = {"ro.build.fingerprint", "ro.boot.flash.locked",
                                   "ro.boot.verifiedbootstate", "ro.boot.vbmeta.device_state", nullptr};
    for (int i = 0; gpkeys[i]; i++) {
        std::string a = prop(gpkeys[i]);
        std::string cmd = std::string("getprop ") + gpkeys[i];
        std::string b = popen_str(cmd.c_str());
        while (!b.empty() && (unsigned char)b.back() <= ' ') b.pop_back();
        if (b.find("popen") == 0 || b.find("skip isolate") != std::string::npos) continue;
        if (!a.empty() && !b.empty() && a != b) {
            p.hit = true;
            d += "getprop vs sys_prop ";
            d += gpkeys[i];
            d += " sys=";
            d += a.substr(0, 60);
            d += " popen=";
            d += b.substr(0, 60);
            d += '\n';
        }
    }
    p.detail = d.empty() ? "prop serial ok" : d;
    if (p.hit) p.detail += "Find Prop Modify Mark";
    return p;
}

Probe probe_attest_boot() {
    Probe p;
    auto flash = prop("ro.boot.flash.locked");
    auto vbmeta = prop("ro.boot.vbmeta.device_state");
    auto vbs = prop("ro.boot.verifiedbootstate");
    bool prop_locked = flash == "1" || vbmeta == "locked";
    bool prop_green = vbs == "green";
    bool att_unlocked = g_attest_detail.find("deviceLocked=false") != std::string::npos;
    bool att_unverified = g_attest_detail.find("verifiedBootState=Unverified") != std::string::npos ||
                          g_attest_detail.find("verifiedBootState=unverified") != std::string::npos;
    p.hit = (prop_locked || prop_green) && (att_unlocked || att_unverified || g_tee_fail);
    p.detail = "flash.locked=" + flash + " vbmeta.device_state=" + vbmeta + " verifiedbootstate=" + vbs +
               "\n" + g_attest_detail;
    if (p.hit) p.detail += "\nAttestation Boot State Contradiction";
    return p;
}

Probe probe_selinux_oracle() {
    Probe p;
    auto ctx = read_file("/sys/fs/selinux/enforce", 8);
    int fd = open("/sys/fs/selinux/context", O_RDWR | O_CLOEXEC);
    p.detail = "enforce=";
    p.detail += ctx.empty() ? "unreadable" : ctx;
    if (fd >= 0) {
        static const char* bad[] = {"u:object_r:magisk_file:s0", "u:object_r:ksu_file:s0",
                                    "u:r:su:s0", "u:object_r:adb_data_file:s0", nullptr};
        char buf[128];
        for (int i = 0; bad[i]; i++) {
            if (write(fd, bad[i], strlen(bad[i])) > 0) {
                p.hit = true;
                p.detail += "\nSELinux accepts ";
                p.detail += bad[i];
            }
        }
        close(fd);
        snprintf(buf, sizeof(buf), "\ncontext fd ok");
        p.detail += buf;
    } else {
        p.detail += "\nSELinux Context Oracle Unavailable";
    }
    DIR* cl = opendir("/sys/fs/selinux/class");
    bool tee_class = false, mark_class = false;
    if (cl) {
        while (dirent* de = readdir(cl)) {
            if (de->d_name[0] == '.') continue;
            if (!strcmp(de->d_name, "tee_service")) tee_class = true;
            if (!strcmp(de->d_name, "magisk") || !strcmp(de->d_name, "ksu") || !strcmp(de->d_name, "zygisk"))
                mark_class = true;
        }
        closedir(cl);
    }
    auto pol = read_file("/sys/fs/selinux/policy", 1 << 20);
    if (pol.find("u:r:su:s0") != std::string::npos || pol.find("magisk_file") != std::string::npos ||
        pol.find("u:r:magisk") != std::string::npos) {
        p.hit = true;
        p.detail += "\nselinux_context has mark : policy";
    }
    bool tee_dev = path_visible("/dev/tee0") || path_visible("/dev/teepriv0") || path_visible("/dev/qseecom") ||
                   path_visible("/dev/trusty-ipc-dev0");
    if (tee_class && !tee_dev) {
        p.hit = true;
        p.detail += "\ncheck selinux env find mark tee_service without TEE device";
    }
    if (mark_class) {
        p.hit = true;
        p.detail += "\ncheck selinux env find mark class";
    }
    if (p.hit) p.detail += "\nAbnormal SELinux Policy Detected";
    else p.detail += "\nSELinux Context Oracle Clean";
    return p;
}

Probe probe_rom_tamper() {
    Probe p;
    auto fp = prop("ro.build.fingerprint");
    auto brand = prop("ro.product.brand");
    auto model = prop("ro.product.model");
    auto device = prop("ro.product.device");
    auto hw = prop("ro.hardware");
    auto last = prop("persist.sys.lastfingerprint");
    auto fl = prop("ro.boot.flash.locked");
    auto vb = prop("ro.boot.verifiedbootstate");
    bool spoof = !fp.empty() && !brand.empty() && fp.find(brand) == std::string::npos &&
                 fp.find(model) == std::string::npos;
    bool unlocked = fl == "0" || vb == "orange" || vb == "yellow";
    bool emu_hw = hw.find("redroid") != std::string::npos || hw.find("goldfish") != std::string::npos ||
                  hw.find("ranchu") != std::string::npos || hw == "vbox" || hw == "generic" ||
                  hw.find("emulator") != std::string::npos;
    std::string gp = popen_str("getprop ro.build.fingerprint");
    while (!gp.empty() && (unsigned char)gp.back() <= ' ') gp.pop_back();
    bool gp_split = !fp.empty() && !gp.empty() && gp.find("popen") != 0 &&
                    gp.find("skip isolate") == std::string::npos && gp != fp;
    bool last_split = !last.empty() && !fp.empty() && fp.find(last) == std::string::npos &&
                      last.find(fp.substr(0, 12)) == std::string::npos;
    p.hit = spoof || unlocked || emu_hw || gp_split || last_split;
    p.detail = "fp=" + fp.substr(0, 80) + " brand=" + brand + " model=" + model + " device=" + device +
               " hardware=" + hw + " lastfp=" + last.substr(0, 40) + " flash.locked=" + fl +
               " verifiedbootstate=" + vb;
    if (gp_split) p.detail += "\ngetprop fingerprint!=" + gp.substr(0, 60);
    if (p.hit) p.detail += "\n当前设备机型&ROM可能被修改!";
    return p;
}

static int pidof_exec(const char* name) {
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;
    pid_t c = fork();
    if (c == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execl("/system/bin/pidof", "pidof", name, (char*)nullptr);
        _exit(127);
    }
    if (c < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    close(pipefd[1]);
    char buf[32] = {};
    read(pipefd[0], buf, sizeof(buf) - 1);
    close(pipefd[0]);
    int st = 0;
    waitpid(c, &st, 0);
    return atoi(buf);
}

Probe probe_system_server_hook() {
    Probe p;
    int pid = pidof_exec("system_server");
    if (pid <= 0) {
        std::string po = popen_str("/system/bin/pidof system_server");
        if (!po.empty() && po.find("popen") != 0 && po.find("skip") == std::string::npos) pid = atoi(po.c_str());
    }
    if (pid <= 0) {
        DIR* d = opendir("/proc");
        if (d) {
            while (dirent* e = readdir(d)) {
                if (e->d_name[0] < '1' || e->d_name[0] > '9') continue;
                char path[64];
                snprintf(path, sizeof(path), "/proc/%s/cmdline", e->d_name);
                auto cmd = read_file(path, 128);
                if (cmd.find("system_server") != std::string::npos &&
                    cmd.find("system_server_dumper") == std::string::npos) {
                    pid = atoi(e->d_name);
                    break;
                }
            }
            closedir(d);
        }
    }
    if (pid <= 0) {
        p.detail = "system_server pid missing";
        return p;
    }
    char mpath[64];
    snprintf(mpath, sizeof(mpath), "/proc/%d/maps", pid);
    auto maps = read_file(mpath, 1 << 20);
    if (maps.empty()) {
        p.detail = "system_server maps unreadable pid=" + std::to_string(pid);
        return p;
    }
    static const char* marks[] = {"redroid", "goldfish", "qemu", "ranchu", "dobby", "xposed",
                                  "frida", "lsposed", "liblsplant", "riru", "substrate", nullptr};
    for (int i = 0; marks[i]; i++) {
        if (blob_has_ci(maps.c_str(), marks[i])) {
            p.hit = true;
            p.detail += "find system server hook ";
            p.detail += marks[i];
            p.detail += '\n';
        }
    }
    if (!p.hit) p.detail = "system_server maps readable pid=" + std::to_string(pid) + " no hook mark";
    else p.detail += "find system server hook";
    return p;
}

Probe probe_tricky_store() {
    Probe p;
    auto maps = read_file("/proc/self/maps");
    if (maps.find("tricky_store") != std::string::npos || maps.find("libpif") != std::string::npos) {
        p.hit = true;
        p.detail += "maps tricky_store/pif\n";
    }
    if (path_visible("/data/adb/tricky_store") || path_visible("/data/adb/modules/tricky_store")) {
        p.hit = true;
        p.detail += "tricky_store module path\n";
    }
    if (!p.hit) p.detail = "no tricky store";
    else p.detail += "Tricky Store Hook";
    return p;
}

Probe probe_verified_boot() {
    Probe p;
    auto v = prop("ro.boot.verifiedbootstate");
    auto vb = prop("ro.boot.vbmeta.device_state");
    p.hit = v == "orange" || v == "yellow" || v == "red" || vb == "unlocked";
    p.detail = "verifiedbootstate=" + v + " vbmeta.device_state=" + vb;
    if (p.hit) p.detail += "\nFind Verified Boot Mark";
    return p;
}

Probe probe_device_unlock() {
    Probe p;
    auto fl = prop("ro.boot.flash.locked");
    auto vb = prop("ro.boot.vbmeta.device_state");
    p.hit = fl == "0" || vb == "unlocked";
    p.detail = "flash.locked=" + fl + " vbmeta.device_state=" + vb;
    if (p.hit) p.detail += "\ntee check device unlock";
    return p;
}

Probe probe_others_process() {
    Probe p;
    DIR* d = opendir("/proc");
    int hits = 0;
    std::string names;
    if (d) {
        while (dirent* e = readdir(d)) {
            if (e->d_name[0] < '1' || e->d_name[0] > '9') continue;
            char path[64];
            snprintf(path, sizeof(path), "/proc/%s/cmdline", e->d_name);
            auto cmd = read_file(path, 128);
            if (cmd.find("magisk") != std::string::npos || cmd.find("ksud") != std::string::npos ||
                cmd.find("apatch") != std::string::npos || cmd.find("zygisk") != std::string::npos) {
                hits++;
                if (names.size() < 200) {
                    names += cmd;
                    names += ' ';
                }
            }
        }
        closedir(d);
    }
    p.hit = hits > 0;
    p.detail = p.hit ? ("Find Others Process " + names) : "no extra root processes";
    return p;
}

Probe probe_gwp_asan() {
    Probe p;
    auto maps = read_file("/proc/self/maps");
    bool has = maps.find("GWP-ASan") != std::string::npos || maps.find("gwp_asan") != std::string::npos;
    // GWP-ASan is a pass/info card, not a risk hit.
    p.hit = false;
    p.detail = has ? "GWP-ASan mapping present (safety check pass)" : "no GWP-ASan maps";
    return p;
}

Probe probe_app_launch() {
    Probe p;
    auto cmd = read_file("/proc/self/cmdline", 256);
    p.hit = false;
    p.detail = "cmdline=";
    p.detail += cmd.empty() ? "?" : cmd.c_str();
    return p;
}

Probe probe_static_integrity() {
    Probe p;
    auto maps = read_file("/proc/self/maps");
    // Check the caller's own native library, so the probe is meaningful in any host.
    Dl_info di {};
    std::string self = "?";
    if (dladdr((const void*)&probe_static_integrity, &di) && di.dli_fname) {
        self = di.dli_fname;
    }
    if (self == "?" || maps.find(self) == std::string::npos) {
        p.hit = true;
        p.detail = "own native library not mapped self=" + self;
    } else if (self.find("(deleted)") != std::string::npos) {
        p.hit = true;
        p.detail = "own native library mapping is deleted self=" + self;
    } else {
        p.detail = "own native library mapped self=" + self;
    }
    return p;
}

Probe probe_partition_mount() {
    Probe p;
    auto mi = read_file("/proc/self/mountinfo");
    p.hit = mi.find(" /system ") != std::string::npos &&
            (mi.find("overlay") != std::string::npos || mi.find("magisk") != std::string::npos);
    p.detail = p.hit ? "system overlay/magisk in mountinfo" : "system mount clean";
    return p;
}

Probe probe_procfs_fd() {
    Probe p;
    auto maps = read_file("/proc/self/maps", 4096);
    auto fdinfo = read_file("/proc/self/fdinfo/0", 256);
    p.hit = maps.empty();
    p.detail = maps.empty() ? "maps unreadable" : "maps readable fdinfo0=" + std::to_string(fdinfo.size());
    return p;
}

Probe probe_apk_integrity() {
    Probe p;
    auto maps = read_file("/proc/self/maps");
    bool apk = maps.find(".apk") != std::string::npos;
    p.hit = !apk;
    p.detail = apk ? "apk mapped" : "no apk in maps";
    return p;
}

Probe probe_network_trust() {
    Probe p;
    auto ux = read_file("/proc/net/unix", 4096);
    p.hit = ux.find("frida") != std::string::npos;
    p.detail = p.hit ? "unix frida" : "unix clean";
    return p;
}

Probe probe_framework_rt() {
    Probe p;
    auto maps = read_file("/proc/self/maps");
    bool fw = maps.find("/system/framework/") != std::string::npos ||
              maps.find("/apex/com.android.art/") != std::string::npos;
    p.hit = !fw;
    p.detail = fw ? "framework/art mapped" : "framework/art missing";
    return p;
}

Probe probe_input_inject() {
    Probe p;
    auto maps = read_file("/proc/self/maps");
    p.hit = maps.find("libinput.so") != std::string::npos && maps.find("uinput") != std::string::npos;
    p.detail = p.hit ? "uinput mapped with libinput" : "no uinput injection maps";
    return p;
}

Probe probe_identity_graph() {
    Probe p;
    auto fp = prop("ro.build.fingerprint");
    auto brand = prop("ro.product.brand");
    auto device = prop("ro.product.device");
    auto name = prop("ro.product.name");
    bool ok = !fp.empty() && (brand.empty() || fp.find(brand) != std::string::npos) &&
              (device.empty() || fp.find(device) != std::string::npos);
    p.hit = !ok;
    p.detail = "fp=" + fp.substr(0, 80) + " brand=" + brand + " device=" + device + " name=" + name;
    return p;
}

static const NamedTech kAll[] = {
        {"su", "Find Root File", probe_su},
        {"magisk_files", "Find Magisk", probe_magisk_files},
        {"magisk_modules", "Magisk modules", probe_magisk_modules},
        {"ksu_apatch", "KSU/APatch", probe_ksu_apatch},
        {"shamiko", "Shamiko", probe_shamiko},
        {"magic_mount", "Magic Mount", probe_magic_mount},
        {"zygisk", "Check Zygisk Injection", probe_zygisk},
        {"xposed", "Find Hook Mark", probe_xposed},
        {"riru", "Riru", probe_riru},
        {"lspd", "LSPosed lspd", probe_lspd},
        {"frida", "Find Frida Mark", probe_frida},
        {"tracer", "TracerPid", probe_tracer},
        {"maps_hide", "Maps Hiding", probe_maps_hide},
        {"mounts", "Mount marks", probe_mounts},
        {"selinux", "SELinux", probe_selinux},
        {"qemu", "Find Simulator Mark", probe_qemu},
        {"vbmeta", "vbmeta", probe_vbmeta},
        {"testkeys", "test-keys", probe_testkeys},
        {"adb", "adbd", probe_adb},
        {"debuggable", "ro.debuggable", probe_debuggable},
        {"dual_user", "Dual user", probe_dual_user},
        {"vpn", "CheckVpn", probe_vpn},
        {"uname", "uname spoof", probe_uname},
        {"elf_crc", "Main Crc Check Error", probe_elf_crc},
        {"iso_crc", "ISO Service Crc Check Error", probe_iso_crc},
        {"twin_crc", "Twin Service Crc Check Error", probe_twin_crc},
        {"crc_locality", "ISO CRC NOT MATCH LOCALITY CRC", probe_crc_locality},
        {"unknown_exec", "Unknown Exec From Main", probe_unknown_exec},
        {"iso_unknown_exec", "Unknown Exec From ISO", probe_iso_unknown_exec},
        {"kernel_runtime", "Kernel Runtime Consistency", probe_kernel_runtime},
        {"hide_uid", "Find Hide Uid", probe_hide_uid},
        {"selinux_iso", "SELinux Runtime Isolation", probe_selinux_isolation},
        {"ksu_sidechannel", "KSU sidechannel", probe_ksu_sidechannel},
        {"avc_log", "AVC log", probe_avc_log},
        {"solist", "solist/GOT", probe_solist},
        {"maps_unread", "maps unread", probe_maps_unread},
        {"embedded_elf", "Embedded ELF", probe_embedded_elf},
        {"odex", "ODEX/OAT", probe_odex},
        {"inline_hook", "Inline Hook", probe_inline_hook},
        {"hwbp", "Hardware Breakpoints", probe_hwbp},
        {"mmap_legality", "mmap legality", probe_mmap_legality},
        {"unidbg", "unidbg env", probe_unidbg},
        {"sandbox_stat", "Partition Stat Spoof (sandbox)", probe_sandbox_stat},
        {"mount_ns", "Mount Namespace Anchor Drift", probe_mount_ns},
        {"bind_mount", "bind mount", probe_bind_mount},
        {"resetprop", "Find Prop Modify Mark", probe_resetprop},
        {"prop_serial", "Find Prop Modify Mark", probe_prop_serial},
        {"attest_boot", "Attestation Boot State Contradiction", probe_attest_boot},
        {"selinux_oracle", "SELinux Policy Oracle Untrusted", probe_selinux_oracle},
        {"rom_tamper", "ROM/model modify", probe_rom_tamper},
        {"ss_hook", "find system server hook", probe_system_server_hook},
        {"tricky_store", "Tricky Store Hook", probe_tricky_store},
        {"verified_boot", "Find Verified Boot Mark", probe_verified_boot},
        {"device_unlock", "device unlock", probe_device_unlock},
        {"others_process", "Find Others Process", probe_others_process},
        {"gwp_asan", "GWP-ASan", probe_gwp_asan},
        {"app_launch", "App Launch Source", probe_app_launch},
        {"static_integrity", "Static Code Integrity", probe_static_integrity},
        {"partition_mount", "System Partition Mount", probe_partition_mount},
        {"procfs_fd", "Procfs/FD Integrity", probe_procfs_fd},
        {"apk_integrity", "APK Integrity", probe_apk_integrity},
        {"network_trust", "Network Trust Local", probe_network_trust},
        {"framework_rt", "Framework Runtime Integrity", probe_framework_rt},
        {"input_inject", "Input Injection", probe_input_inject},
        {"identity_graph", "Device Identity Graph", probe_identity_graph},
        {"build_identity", "Build Identity Source Mismatch", probe_build_identity},
        {"boot_time", "Boot time", probe_boot_time},
        {"apexd_boot", "Find Apexd Boot Time", probe_apexd_boot},
        {"ptrace_nspid", "NSpid/PPid", probe_ptrace_nspid},
        {"seccomp", "seccomp", probe_seccomp},
        {"attestation", "Attestation/TEE", probe_attestation},
        {"aosp_key", "AOSP attestation key", probe_aosp_key},
        {"keybox", "Tampered keybox", probe_keybox},
        {"isolate_diff", "Futile Hide isolate-diff", probe_isolate_diff},
        {"zygisk_assistant", "Futile Hide Zygisk-Assistant", probe_zygisk_assistant},
        {"peekaboo", "Futile Hide Peekaboo", probe_peekaboo},
        {"umount_detach", "Futile Hide umount/detach", probe_umount_detach},
        {"dex2oat_mount", "Futile Hide dex2oat", probe_dex2oat_mount},
        {"fingerprint", "fingerprint collect", probe_fingerprint},
        {"art_method", "ArtMethod", probe_art_method},
};

const NamedTech* all_techniques(int* n) {
    *n = (int)(sizeof(kAll) / sizeof(kAll[0]));
    return kAll;
}
