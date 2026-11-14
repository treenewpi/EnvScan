#include "probes.h"

#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <linux/limits.h>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <cerrno>
#include <csignal>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/system_properties.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <cctype>
#include <ctime>
#include <cmath>
#include <vector>
#include <dlfcn.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/auxv.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>

#ifndef SYS_faccessat
#define SYS_faccessat 48
#endif
#ifndef SYS_openat
#define SYS_openat 56
#endif
#ifndef SYS_newfstatat
#define SYS_newfstatat 79
#endif
#ifndef SYS_prctl
#define SYS_prctl 167
#endif
#ifndef SYS_statx
#define SYS_statx 291
#endif
#ifndef SYS_getpid
#define SYS_getpid 172
#endif
#ifndef SYS_uname
#define SYS_uname 160
#endif
#ifndef SYS_getuid
#define SYS_getuid 174
#endif
#ifndef PR_GET_NO_NEW_PRIVS
#define PR_GET_NO_NEW_PRIVS 39
#endif
#ifndef PR_GET_SECCOMP
#define PR_GET_SECCOMP 21
#endif
#ifndef SYS_unlinkat
#define SYS_unlinkat 35
#endif
#ifndef SYS_perf_event_open
#define SYS_perf_event_open 241
#endif
#ifndef HWCAP_AES
#define HWCAP_AES (1 << 3)
#endif
#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef AT_NO_AUTOMOUNT
#define AT_NO_AUTOMOUNT 0x800
#endif
#define KSU_OPTION 0xDEADBEEF
#define KSU_CMD_GET_VERSION 2
#define KSU_CMD_UID_SHOULD_UMOUNT 8
#define KSU_CMD_GET_MANAGER_UID 9
#define KSU_CMD_HOOK_TYPE 10
#define KSU_CMD_IS_KPM_ENABLED 13

bool blob_has_ci(const char* hay, const char* needle) {
    if (!hay || !needle || !*needle) return false;
    size_t nlen = strlen(needle);
    for (const char* p = hay; *p; p++) {
        size_t i = 0;
        for (; i < nlen && p[i]; i++) {
            if (tolower((unsigned char)p[i]) != tolower((unsigned char)needle[i])) break;
        }
        if (i == nlen) return true;
        if (!p[i]) return false;
    }
    return false;
}

static volatile sig_atomic_t g_sigsys = 0;
static void on_sigsys(int) { g_sigsys = 1; }
static struct SigSysArm {
    SigSysArm() { signal(SIGSYS, on_sigsys); }
} g_sigsys_arm;

static volatile int g_cntvct_ok = -1;

uint64_t ticks_now() {
#if defined(__aarch64__)
    if (g_cntvct_ok != 0) {
        uint64_t t = 0;
        asm volatile("mrs %0, cntvct_el0" : "=r"(t));
        if (t != 0) g_cntvct_ok = 1;
        if (g_cntvct_ok == 1) return t;
    }
#endif
    struct timespec ts {};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

TickStat ticks_stat(const uint64_t* v, int n, int skip) {
    TickStat s;
    if (!v || n <= skip) return s;
    int m = n - skip;
    double sum = 0;
    for (int i = skip; i < n; i++) sum += (double)v[i];
    s.avg = sum / (double)m;
    double var = 0;
    for (int i = skip; i < n; i++) {
        double d = (double)v[i] - s.avg;
        var += d * d;
    }
    s.dev = std::sqrt(var / (double)m);
    s.n = m;
    return s;
}

long svc5(long nr, long a0, long a1, long a2, long a3, long a4) {
#if defined(__aarch64__)
    register long x8 asm("x8") = nr;
    register long x0 asm("x0") = a0;
    register long x1 asm("x1") = a1;
    register long x2 asm("x2") = a2;
    register long x3 asm("x3") = a3;
    register long x4 asm("x4") = a4;
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8) : "memory", "cc");
    return x0;
#else
    return syscall(nr, a0, a1, a2, a3, a4);
#endif
}

static int from_svc(long rc, int* err) {
    if (rc < 0 && rc >= -4095) {
        *err = (int)(-rc);
        return -1;
    }
    *err = 0;
    return (int)rc;
}

PathObs observe_path(const char* path) {
    PathObs o;
    if (!path || !*path) return o;
    errno = 0;
    o.libc_rc = faccessat(AT_FDCWD, path, F_OK, 0);
    o.libc_err = o.libc_rc == 0 ? 0 : errno;
    errno = 0;
    o.sys_rc = (int)syscall(SYS_faccessat, AT_FDCWD, path, F_OK, 0);
    o.sys_err = o.sys_rc == 0 ? 0 : errno;
    int err = 0;
    g_sigsys = 0;
    long rc = svc5(SYS_faccessat, AT_FDCWD, (long)path, F_OK, 0, 0);
    o.svc_rc = g_sigsys ? -1 : from_svc(rc, &err);
    o.svc_err = g_sigsys ? EPERM : err;
    char stx[256] = {};
    g_sigsys = 0;
    rc = svc5(SYS_statx, AT_FDCWD, (long)path, AT_NO_AUTOMOUNT, 0x7ff, (long)stx);
    err = 0;
    o.stx_rc = g_sigsys ? -1 : from_svc(rc, &err);
    o.stx_err = g_sigsys ? EPERM : err;
    if (o.stx_rc != 0 && o.stx_err != 0) {
        struct stat st {};
        g_sigsys = 0;
        rc = svc5(SYS_newfstatat, AT_FDCWD, (long)path, (long)&st, 0, 0);
        err = 0;
        int frc = g_sigsys ? -1 : from_svc(rc, &err);
        if (frc == 0) {
            o.stx_rc = 0;
            o.stx_err = 0;
        }
    }
    return o;
}

bool obs_exists(const PathObs& o) {
    return o.libc_rc == 0 || o.sys_rc == 0 || o.svc_rc == 0 || o.stx_rc == 0;
}

bool obs_denied(const PathObs& o) {
    if (obs_exists(o)) return false;
    auto d = [](int rc, int err) { return rc != 0 && (err == EACCES || err == EPERM); };
    // faccessat/syscall/SVC only. statx EACCES on MIUI is not "present".
    return d(o.libc_rc, o.libc_err) || d(o.sys_rc, o.sys_err) || d(o.svc_rc, o.svc_err);
}

bool obs_diverge(const PathObs& o) {
    return o.libc_rc != o.svc_rc || (o.libc_rc != 0 && o.libc_err != o.svc_err && o.svc_err != 0);
}

bool path_visible(const char* path) {
    if (!path || !*path) return false;
    PathObs o = observe_path(path);
    if (obs_exists(o)) return true;
    g_sigsys = 0;
    long fd = svc5(SYS_openat, AT_FDCWD, (long)path, O_RDONLY | O_CLOEXEC, 0, 0);
    if (!g_sigsys && fd >= 0) {
        close((int)fd);
        return true;
    }
    fd = svc5(SYS_openat, AT_FDCWD, (long)path, O_PATH | O_CLOEXEC, 0, 0);
    if (!g_sigsys && fd >= 0) {
        close((int)fd);
        return true;
    }
    return false;
}

static bool exists_path(const char* p) {
    return path_visible(p);
}

static int dir_ents(const char* path, char* names, size_t nsz);

struct AdbView {
    PathObs adb;
    bool present = false;
    bool searchable = false;
    int ents = -1;
    char names[96] = "-";
};

static AdbView inspect_adb() {
    AdbView v;
    v.adb = observe_path("/data/adb");
    v.present = obs_exists(v.adb);
    v.ents = dir_ents("/data/adb", v.names, sizeof(v.names));
    v.searchable = v.ents >= 0;
    return v;
}

static bool child_denied(const PathObs& child, bool parent_searchable) {
    return parent_searchable && obs_denied(child);
}

static std::string read_file(const char* path, size_t maxn = 1 << 20);

static bool g_cls_xposed = false, g_cls_lsp = false;
static bool g_pkg_ksu = false, g_pkg_magisk = false, g_pkg_lsp = false;
static bool g_stack_lsp = false, g_cl_lsp = false, g_dex_lsp = false, g_xp_meta = false;
static std::string g_java_pkgs;
static std::string g_iso_snap;

void set_java_findings(bool xposed_cls, bool lsposed_cls, bool magisk_pkg, bool ksu_pkg, bool lsp_pkg,
                      bool stack_lsp, bool cl_lsp, bool dex_lsp, bool xp_meta,
                      const std::string& pkgs) {
    g_cls_xposed = xposed_cls;
    g_cls_lsp = lsposed_cls;
    g_pkg_magisk = magisk_pkg;
    g_pkg_ksu = ksu_pkg;
    g_pkg_lsp = lsp_pkg;
    g_stack_lsp = stack_lsp;
    g_cl_lsp = cl_lsp;
    g_dex_lsp = dex_lsp;
    g_xp_meta = xp_meta;
    g_java_pkgs = pkgs;
}

void set_isolate_snap(const std::string& snap) { g_iso_snap = snap; }
const std::string& isolate_snap() { return g_iso_snap; }

static std::string g_twin_snap;
void set_twin_snap(const std::string& snap) { g_twin_snap = snap; }
const std::string& twin_snap() { return g_twin_snap; }

std::string snap_str(const std::string& s, const char* key) {
    if (s.empty() || !key) return {};
    std::string k = std::string(key) + "=";
    auto pos = s.find(k);
    if (pos == std::string::npos) return {};
    auto start = pos + k.size();
    auto end = s.find(' ', start);
    return s.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

bool ksu_ksuctl(int cmd, void* arg1, void* arg2, int32_t* result_out) {
    int32_t result = 0;
    g_sigsys = 0;
    svc5(SYS_prctl, (long)KSU_OPTION, cmd, (long)arg1, (long)arg2, (long)&result);
    if (result == (int32_t)KSU_OPTION) {
        if (result_out) *result_out = result;
        return true;
    }
    int32_t result2 = 0;
    prctl((int)KSU_OPTION, cmd, arg1, arg2, &result2);
    if (result_out) *result_out = result2 != 0 ? result2 : result;
    return result2 == (int32_t)KSU_OPTION;
}

int snap_field(const std::string& s, const char* key) {
    if (s.empty() || !key) return -999;
    std::string k = std::string(key) + "=";
    auto pos = s.find(k);
    if (pos == std::string::npos) return -999;
    return atoi(s.c_str() + pos + k.size());
}

std::string unix_hits(const char* const* needles) {
    auto ux = read_file("/proc/net/unix");
    std::string h;
    if (ux.empty()) return h;
    for (int i = 0; needles[i]; i++) {
        if (blob_has_ci(ux.c_str(), needles[i])) {
            if (!h.empty()) h += ',';
            h += needles[i];
        }
    }
    return h;
}

std::string leak_hits(const char* const* needles) {
    std::string h;
    auto add = [&](const char* src, const char* s) {
        if (!s || !*s) return;
        for (int i = 0; needles[i]; i++) {
            if (!blob_has_ci(s, needles[i])) continue;
            if (!h.empty()) h += ',';
            h += src;
            h += ':';
            h += needles[i];
        }
    };
    DIR* d = opendir("/proc/self/fd");
    if (d) {
        char link[256], path[64];
        while (auto* e = readdir(d)) {
            if (e->d_name[0] == '.') continue;
            snprintf(path, sizeof(path), "/proc/self/fd/%s", e->d_name);
            ssize_t n = readlink(path, link, sizeof(link) - 1);
            if (n > 0) {
                link[n] = 0;
                add("fd", link);
            }
        }
        closedir(d);
    }
    auto env = read_file("/proc/self/environ", 1 << 16);
    for (size_t i = 0; i < env.size(); i++)
        if (env[i] == 0) env[i] = '\n';
    add("env", env.c_str());
    add("kmod", read_file("/proc/modules", 1 << 16).c_str());
    add("ksym", read_file("/proc/kallsyms", 1 << 16).c_str());
    return h;
}

static std::string ns_mnt(const char* procdir) {
    char path[64], buf[128];
    snprintf(path, sizeof(path), "%s/ns/mnt", procdir);
    ssize_t n = readlink(path, buf, sizeof(buf) - 1);
    if (n <= 0) return {};
    buf[n] = 0;
    return buf;
}

static int phdr_has(const char* needle) {
    struct Ctx {
        const char* n;
        int hit;
    } ctx{needle, 0};
    dl_iterate_phdr(
            [](struct dl_phdr_info* info, size_t, void* data) -> int {
                auto* c = (Ctx*)data;
                if (info->dlpi_name && blob_has_ci(info->dlpi_name, c->n)) c->hit = 1;
                return 0;
            },
            &ctx);
    return ctx.hit;
}

static int dir_ents(const char* path, char* names, size_t nsz) {
    if (names && nsz) names[0] = 0;
    DIR* d = opendir(path);
    if (!d) return -1;
    int n = 0;
    while (auto* e = readdir(d)) {
        if (e->d_name[0] == '.') continue;
        n++;
        if (!names || !nsz) continue;
        size_t used = strlen(names);
        size_t add = strlen(e->d_name);
        if (used + add + 2 < nsz) {
            if (used) {
                names[used] = ',';
                names[used + 1] = 0;
                used++;
            }
            memcpy(names + used, e->d_name, add + 1);
        }
    }
    closedir(d);
    if (names && nsz && !names[0]) {
        names[0] = '-';
        names[1] = 0;
    }
    return n;
}

std::string iso_snapshot() {
    auto adb = observe_path("/data/adb");
    auto mag = observe_path("/data/adb/magisk");
    auto ksu = observe_path("/data/adb/ksu");
    auto mods = observe_path("/data/adb/modules");
    auto sha = observe_path("/debug_ramdisk/shamiko/module.prop");
    auto su = observe_path("/system/bin/su");
    auto maps = read_file("/proc/self/maps", 1 << 18);
    int32_t ver = 0, result = 0, umount = 0, mgr = 0;
    bool cookie = ksu_ksuctl(KSU_CMD_GET_VERSION, &ver, nullptr, &result);
    int32_t r2 = 0;
    ksu_ksuctl(KSU_CMD_UID_SHOULD_UMOUNT, &umount, nullptr, &r2);
    int32_t r3 = 0;
    ksu_ksuctl(KSU_CMD_GET_MANAGER_UID, &mgr, nullptr, &r3);
    const char* uxneed[] = {"magisk", "ksud", "zygisk", "lspd", "shamiko", "apatch", nullptr};
    auto ux = unix_hits(uxneed);
    char adb_n[96] = "-";
    int adb_ents = dir_ents("/data/adb", adb_n, sizeof(adb_n));
    auto se = read_file("/proc/self/attr/current", 256);
    while (!se.empty() && (unsigned char)se.back() <= ' ') se.pop_back();
    auto st = read_file("/proc/self/status", 4096);
    auto status_i = [&](const char* k) {
        auto pos = st.find(k);
        if (pos == std::string::npos) return -1;
        return atoi(st.c_str() + pos + strlen(k));
    };
    int nnp_pr = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    long nnp_raw = svc5(SYS_prctl, PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    int sc_pr = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    long sc_raw = svc5(SYS_prctl, PR_GET_SECCOMP, 0, 0, 0, 0);
    int nnp_st = status_i("NoNewPrivs:");
    int sc_st = status_i("Seccomp:");
    Probe ue = probe_unknown_exec();
    int unk = 0;
    auto up = ue.detail.find("unknown=");
    if (up != std::string::npos) unk = atoi(ue.detail.c_str() + up + 8);
    std::string miss;
    auto mp = ue.detail.find("misspages=");
    if (mp != std::string::npos) {
        auto nl = ue.detail.find('\n', mp);
        size_t n = (nl == std::string::npos) ? 180 : (nl - mp);
        if (n > 180) n = 180;
        miss = ue.detail.substr(mp, n);
    }
    struct utsname u {};
    uname(&u);
    struct utsname ur {};
    long urc = svc5(SYS_uname, (long)&ur, 0, 0, 0, 0);
    if (urc < 0 && urc >= -4095) ur.release[0] = 0;
    long pgsz = sysconf(_SC_PAGESIZE);
    unsigned long auxp = getauxval(AT_PAGESZ);
    char buf[1400];
    snprintf(buf, sizeof(buf),
             "uid=%d tracer=%d su=%d adb_libc=%d/%d adb_sys=%d/%d adb_svc=%d/%d adb_denied=%d "
             "mag=%d mag_err=%d ksu=%d ksu_err=%d mods=%d mods_err=%d shamiko=%d "
             "adb_ents=%d adb_n=%s maps_magisk=%d maps_ksu=%d maps_lsp=%d "
             "ksu_cookie=%d ksu_ver=%d ksu_umount=%d ksu_mgr=%d unix=%s "
             "se=%s nnp_pr=%d nnp_raw=%ld nnp_st=%d sc_pr=%d sc_raw=%ld sc_st=%d unk=%d "
             "pagesz=%ld auxp=%lu uname=%s rawuname=%s",
             (int)getuid(), tracer_pid(), obs_exists(su) ? 1 : 0, adb.libc_rc, adb.libc_err, adb.sys_rc,
             adb.sys_err, adb.svc_rc, adb.svc_err, obs_denied(adb) ? 1 : 0, obs_exists(mag) ? 1 : 0,
             mag.svc_err, obs_exists(ksu) ? 1 : 0, ksu.svc_err, obs_exists(mods) ? 1 : 0, mods.svc_err,
             obs_exists(sha) ? 1 : 0, adb_ents, adb_n, blob_has_ci(maps.c_str(), "magisk") ? 1 : 0,
             (blob_has_ci(maps.c_str(), "kernelsu") || blob_has_ci(maps.c_str(), "ksud")) ? 1 : 0,
             (blob_has_ci(maps.c_str(), "lspd") || blob_has_ci(maps.c_str(), "lsposed") ||
              blob_has_ci(maps.c_str(), "liblsplant"))
                     ? 1
                     : 0,
             cookie ? 1 : 0, (int)ver, (int)umount, (int)mgr, ux.empty() ? "-" : ux.c_str(),
             se.empty() ? "-" : se.c_str(), nnp_pr, nnp_raw, nnp_st, sc_pr, sc_raw, sc_st, unk, pgsz, auxp,
             u.release, ur.release[0] ? ur.release : "-");
    std::string out = buf;
    if (!miss.empty()) {
        out += " ";
        out += miss;
    }
    out += " ";
    out += mount_ns_pack();
    return out;
}

static std::string read_file(const char* path, size_t maxn) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        long sfd = svc5(SYS_openat, AT_FDCWD, (long)path, O_RDONLY | O_CLOEXEC, 0, 0);
        if (sfd < 0) return {};
        fd = (int)sfd;
    }
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

std::string sys_prop(const char* k) {
    if (!k || !*k) return {};
    char v[PROP_VALUE_MAX] = {};
    __system_property_get(k, v);
    return v;
}

static std::string prop(const char* k) { return sys_prop(k); }

static std::string join_hits(const char* const* paths) {
    std::string hits;
    for (int i = 0; paths[i]; i++) {
        if (exists_path(paths[i])) {
            if (!hits.empty()) hits += '\n';
            hits += paths[i];
        }
    }
    return hits;
}

static const char* kSu[] = {
        "/system/bin/su","/system/xbin/su","/sbin/su","/sbin/nvsu","/su/bin/su",
        "/cache/su","/data/local/su","/data/local/bin/su","/data/local/xbin/su",
        "/debug_ramdisk/su","/system/bin/.ext/su","/system/bin/.ext/.su",
        "/vendor/bin/su","/vendor/xbin/su","/odm/bin/su","/product/bin/su",
        "/system_ext/bin/su","/apex/com.android.runtime/bin/su","/su/bin/su",
        nullptr};
static const char* kMagisk[] = {
        "/sbin/.magisk","/data/adb/magisk","/data/magisk.apk","/system/bin/magisk",
        "/system/bin/magisk32","/system/etc/init/magisk.rc","/cache/magisk.log",
        "/dev/magisk/img","/data/adb/modules","/data/adb/modules/","/debug_ramdisk/.magisk",
        "/debug_ramdisk/magisk", nullptr};
static const char* kKsu[] = {
        "/data/adb/kpatch","/data/adb/ksu","/data/adb/ksud","/data/adb/ksu/bin",
        "/data/adb/apd","/data/adb/ap","/data/adb/ap/bin",
        "/data/adb/ap/version","/data/adb/ap/log/bin/kpatch","/data/adb/ap/log/bin/apd",
        "/data/adb/ap/log/bin/magiskpolicy","/data/adb/ap/su_path",
        nullptr};

std::string modules_matching(const char* needle) {
    std::string out;
    if (!needle || !*needle) return out;
    const char* roots[] = {"/data/adb/modules", "/data/adb/modules_update",
                           "/sbin/.magisk/modules", "/debug_ramdisk/.magisk/modules", nullptr};
    for (int r = 0; roots[r]; r++) {
        DIR* d = opendir(roots[r]);
        if (!d) continue;
        while (auto* e = readdir(d)) {
            if (e->d_name[0] == '.') continue;
            char prop[PATH_MAX];
            snprintf(prop, sizeof(prop), "%s/%s/module.prop", roots[r], e->d_name);
            auto body = read_file(prop, 4096);
            if (!blob_has_ci(e->d_name, needle) && !blob_has_ci(body.c_str(), needle)) continue;
            if (!out.empty()) out += '\n';
            out += roots[r];
            out += '/';
            out += e->d_name;
            auto idp = body.find("id=");
            if (idp != std::string::npos) {
                auto end = body.find('\n', idp);
                out += " ";
                out += body.substr(idp, end == std::string::npos ? std::string::npos : end - idp);
            }
        }
        closedir(d);
    }
    return out;
}

static Probe from_paths(const char* const* paths, const char* extra = nullptr) {
    Probe p;
    p.detail = join_hits(paths);
    if (extra && exists_path(extra)) {
        if (!p.detail.empty()) p.detail += '\n';
        p.detail += extra;
    }
    p.hit = !p.detail.empty();
    return p;
}

Probe probe_su() {
    Probe p = from_paths(kSu);
    const char* path = getenv("PATH");
    if (path) {
        std::string copy = path;
        char* save = nullptr;
        for (char* tok = strtok_r(copy.data(), ":", &save); tok; tok = strtok_r(nullptr, ":", &save)) {
            char buf[PATH_MAX];
            snprintf(buf, sizeof(buf), "%s/su", tok);
            if (exists_path(buf)) {
                p.hit = true;
                if (!p.detail.empty()) p.detail += '\n';
                p.detail += buf;
            }
        }
    }
    auto su = observe_path("/system/bin/su");
    if (obs_diverge(su)) {
        p.hit = true;
        p.detail += "\nlibc/svc diverge su";
    }
    if (obs_denied(su)) {
        p.hit = true;
        p.detail += "\nsu EACCES/EPERM (present, hidden)";
    }
    if (!g_iso_snap.empty() && snap_field(g_iso_snap, "su") == 1 && !obs_exists(su)) {
        p.hit = true;
        p.detail += "\nisolate sees su, main does not";
    }
    if (!p.hit) p.detail = "no su";
    return p;
}
Probe probe_magisk_files() {
    auto p = from_paths(kMagisk);
    auto maps = read_file("/proc/self/maps");
    auto mi = read_file("/proc/self/mountinfo");
    if (blob_has_ci(maps.c_str(), "magisk") || blob_has_ci(maps.c_str(), ".magisk")) {
        p.hit = true;
        p.detail += "\nmaps magisk";
    }
    if (blob_has_ci(mi.c_str(), "magisk")) {
        p.hit = true;
        p.detail += "\nmountinfo magisk";
    }
    DIR* d = opendir("/debug_ramdisk");
    if (d) {
        while (auto* e = readdir(d)) {
            if (e->d_name[0] == '.') continue;
            if (blob_has_ci(e->d_name, "magisk")) {
                p.hit = true;
                p.detail += "\n/debug_ramdisk/";
                p.detail += e->d_name;
            }
        }
        closedir(d);
    }
    const char* uxneed[] = {"magisk", "magiskd", nullptr};
    auto ux = unix_hits(uxneed);
    if (!ux.empty()) {
        p.hit = true;
        p.detail += "\nunix " + ux;
    }
    auto adb = inspect_adb();
    auto mag = observe_path("/data/adb/magisk");
    // Stock USB debugging uses 700 /data/adb for adb_keys. That is not Magisk.
    if (child_denied(mag, adb.searchable)) {
        p.hit = true;
        p.detail += "\n/data/adb/magisk EACCES (parent searchable)";
    }
    if (obs_diverge(adb.adb) || (adb.searchable && obs_diverge(mag))) {
        p.hit = true;
        p.detail += "\nlibc/svc diverge /data/adb";
    }
    const char* leaks[] = {"magisk", "magiskd", nullptr};
    auto leak = leak_hits(leaks);
    if (!leak.empty()) {
        p.hit = true;
        p.detail += "\nleak " + leak;
    }
    if (g_pkg_magisk) {
        p.hit = true;
        p.detail += "\nmagisk pkg ";
        p.detail += g_java_pkgs;
    }
    if (!g_iso_snap.empty() && snap_field(g_iso_snap, "mag") == 1 && !obs_exists(mag)) {
        p.hit = true;
        p.detail += "\nisolate sees magisk, main does not";
    }
    if (!p.hit) p.detail = "no magisk paths";
    return p;
}
Probe probe_magisk_modules() {
    Probe p;
    const char* roots[] = {"/data/adb/modules", "/data/adb/modules_update", nullptr};
    std::string hits;
    int n = 0;
    auto adb = inspect_adb();
    for (int i = 0; roots[i]; i++) {
        auto o = observe_path(roots[i]);
        if (child_denied(o, adb.searchable)) {
            p.hit = true;
            hits += roots[i];
            hits += " EACCES (parent searchable)\n";
        }
        if (adb.searchable && obs_diverge(o)) {
            p.hit = true;
            hits += roots[i];
            hits += " libc/svc diverge\n";
        }
        DIR* d = opendir(roots[i]);
        if (!d) continue;
        while (auto* e = readdir(d)) {
            if (e->d_name[0] == '.') continue;
            char buf[PATH_MAX];
            snprintf(buf, sizeof(buf), "%s/%s/module.prop", roots[i], e->d_name);
            if (exists_path(buf)) {
                n++;
                if (!hits.empty()) hits += '\n';
                hits += e->d_name;
            }
        }
        closedir(d);
    }
    if (!g_iso_snap.empty() && snap_field(g_iso_snap, "mods") == 1 && n == 0) {
        p.hit = true;
        hits += "isolate sees modules, main does not\n";
    }
    p.hit = p.hit || n > 0;
    if (!p.hit && adb.present && !adb.searchable)
        p.detail = "no module.prop ( /data/adb present, not searchable )";
    else
        p.detail = p.hit ? hits : "no modules";
    return p;
}
Probe probe_ksu_apatch() {
    auto p = from_paths(kKsu);
    auto maps = read_file("/proc/self/maps");
    auto mi = read_file("/proc/self/mountinfo");
    if (blob_has_ci(maps.c_str(), "kernelsu") || blob_has_ci(maps.c_str(), "kpatch") ||
        blob_has_ci(maps.c_str(), "apatch") || blob_has_ci(maps.c_str(), "ksud")) {
        p.hit = true;
        p.detail += "\nmaps ksu/apatch";
    }
    if (blob_has_ci(mi.c_str(), "kernelsu") || blob_has_ci(mi.c_str(), "apatch")) {
        p.hit = true;
        p.detail += "\nmountinfo ksu/apatch";
    }
    if (path_visible("/sys/module/kernelsu") || path_visible("/proc/ksu")) {
        p.hit = true;
        p.detail += "\nksu sysfs/proc";
    }
    auto adb = observe_path("/data/adb/ksu");
    auto adbroot = inspect_adb();
    if (adbroot.present && !adbroot.searchable) {
        p.detail += "\n/data/adb present, not searchable";
    }
    if (child_denied(adb, adbroot.searchable)) {
        p.hit = true;
        p.detail += "\n/data/adb/ksu EACCES (parent searchable)";
    }
    if (adbroot.searchable && (obs_diverge(adb) || obs_diverge(adbroot.adb))) {
        p.hit = true;
        p.detail += "\nlibc/svc diverge ksu";
    }
    int32_t ver = 0, result = 0, umount = 0, mgr = 0;
    bool cookie = ksu_ksuctl(KSU_CMD_GET_VERSION, &ver, nullptr, &result);
    ksu_ksuctl(KSU_CMD_UID_SHOULD_UMOUNT, &umount, nullptr, &result);
    ksu_ksuctl(KSU_CMD_GET_MANAGER_UID, &mgr, nullptr, &result);
    if (cookie || ver > 0) {
        p.hit = true;
        p.detail += "\nksuctl cookie ver=" + std::to_string(ver);
    }
    if (umount) {
        p.hit = true;
        p.detail += "\nksu uid_should_umount=1";
    }
    if (mgr > 0) {
        p.hit = true;
        p.detail += "\nksu manager_uid=" + std::to_string(mgr);
    }
    const char* uxneed[] = {"ksud", "kernelsu", "apatch", nullptr};
    auto ux = unix_hits(uxneed);
    if (!ux.empty()) {
        p.hit = true;
        p.detail += "\nunix " + ux;
    }
    const char* leaks[] = {"kernelsu", "ksud", "kpatch", "apatch", nullptr};
    auto leak = leak_hits(leaks);
    if (!leak.empty()) {
        p.hit = true;
        p.detail += "\nleak " + leak;
    }
    if (g_pkg_ksu) {
        p.hit = true;
        p.detail += "\npkg=";
        p.detail += g_java_pkgs;
    }
    if (!g_iso_snap.empty()) {
        if (snap_field(g_iso_snap, "ksu") == 1 && !obs_exists(adb)) {
            p.hit = true;
            p.detail += "\nisolate sees ksu files, main does not";
        }
        if (snap_field(g_iso_snap, "ksu_cookie") == 1 && !cookie) {
            p.hit = true;
            p.detail += "\nisolate ksuctl cookie, main hooked";
        }
    }
    if (!p.hit) p.detail = "no ksu/apatch";
    return p;
}

Probe probe_zygisk() {
    Probe p;
    auto maps = read_file("/proc/self/maps");
    if (maps.find("libzygisk") != std::string::npos || maps.find("libzygisk_loader") != std::string::npos ||
        maps.find("zygisk_next") != std::string::npos || maps.find("rezygisk") != std::string::npos) {
        p.hit = true;
        p.detail = "maps zygisk";
    }
    if (phdr_has("zygisk")) {
        p.hit = true;
        p.detail += "\ndl_iterate_phdr zygisk";
    }
    if (exists_path("/system/lib64/libzygisk.so") || exists_path("/system/lib64/libzygisk_loader.so")) {
        p.hit = true;
        p.detail += "\nlibzygisk.so";
    }
    const char* ld = getenv("LD_PRELOAD");
    if (ld && *ld && blob_has_ci(ld, "zygisk")) {
        p.hit = true;
        p.detail += std::string("\nLD_PRELOAD=") + ld;
    }
    auto nb = prop("ro.dalvik.vm.native.bridge");
    if (!nb.empty() && nb != "0" && blob_has_ci(nb.c_str(), "zygisk")) {
        p.hit = true;
        p.detail += "\nnative.bridge=" + nb;
    }
    const char* uxneed[] = {"zygisk", nullptr};
    auto ux = unix_hits(uxneed);
    if (!ux.empty()) {
        p.hit = true;
        p.detail += "\nunix " + ux;
    }
    const char* leaks[] = {"zygisk", nullptr};
    auto leak = leak_hits(leaks);
    if (!leak.empty()) {
        p.hit = true;
        p.detail += "\nleak " + leak;
    }
    if (!p.hit) p.detail = "no zygisk";
    return p;
}

Probe probe_xposed() {
    static const char* xs[] = {
            "/system/lib64/libxposed_art.so","/system/lib/libxposed_art.so",
            "/system/framework/XposedBridge.jar","/system/xposed.prop",
            "/sbin/.magisk/modules/zygisk_lsposed","/sbin/.magisk/modules/riru_lsposed",
            nullptr};
    auto maps = read_file("/proc/self/maps");
    Probe p = from_paths(xs);
    if (maps.find("xposed") != std::string::npos || maps.find("LSPHooker") != std::string::npos ||
        maps.find("lsposed") != std::string::npos || maps.find("liblsplant") != std::string::npos) {
        p.hit = true;
        p.detail += "\nmaps xposed/lsposed/lsplant";
    }
    if (g_cls_xposed || g_cls_lsp) {
        p.hit = true;
        p.detail += "\nFindClass Xposed/LSPosed";
    }
    if (g_stack_lsp) {
        p.hit = true;
        p.detail += "\nstacktrace lspd/xposed";
    }
    if (g_cl_lsp) {
        p.hit = true;
        p.detail += "\nClassLoader lspd";
    }
    if (g_dex_lsp) {
        p.hit = true;
        p.detail += "\ndexElements lspd";
    }
    auto oat = prop("dalvik.vm.dex2oat-flags");
    if (!oat.empty()) {
        p.hit = true;
        p.detail += "\ndalvik.vm.dex2oat-flags=";
        p.detail += oat;
    }
    if (phdr_has("lsplant") || phdr_has("lspd")) {
        p.hit = true;
        p.detail += "\ndl_iterate_phdr lspd/lsplant";
    }
    // Hook mark covers XposedBridge / maps / dex2oat-flags / hooked methods.
    // xposedminversion on a 3rd-party APK is an unactivated module sitting on
    // disk, which is reported as a note rather than a hit.
    if (g_xp_meta) {
        p.detail += "\nxposedminversion metadata (module APK, not hook)";
    }
    if (!g_java_pkgs.empty() && p.hit) {
        p.detail += "\n";
        p.detail += g_java_pkgs;
    } else if (!p.hit && g_xp_meta && !g_java_pkgs.empty()) {
        p.detail += "\n";
        p.detail += g_java_pkgs;
    }
    if (!p.hit && p.detail.empty()) p.detail = "no xposed";
    return p;
}

Probe probe_frida() {
    Probe p;
    auto maps = read_file("/proc/self/maps");
    auto ux = read_file("/proc/net/unix");
    if (maps.find("frida") != std::string::npos || maps.find("gadget") != std::string::npos ||
        maps.find("linjector") != std::string::npos) {
        p.hit = true;
        p.detail += "maps frida/gadget/linjector\n";
    }
    if (ux.find("frida") != std::string::npos || ux.find("linjector") != std::string::npos) {
        p.hit = true;
        p.detail += "unix frida/linjector\n";
    }
    if (!p.hit) p.detail = "no frida";
    return p;
}

Probe probe_selinux() {
    Probe p;
    auto e = read_file("/sys/fs/selinux/enforce");
    if (e.empty()) {
        p.hit = false;
        p.detail = "enforce unreadable";
        return p;
    }
    p.hit = e.find('0') != std::string::npos;
    p.detail = p.hit ? "Permissive" : "Enforcing";
    return p;
}

int tracer_pid() {
    auto st = read_file("/proc/self/status");
    auto pos = st.find("TracerPid:");
    if (pos == std::string::npos) return -1;
    return atoi(st.c_str() + pos + 10);
}

Probe probe_tracer() {
    Probe p;
    int tp = tracer_pid();
    p.hit = tp > 0;
    p.detail = "TracerPid=" + std::to_string(tp);
    if (g_iso_snap.find("tracer=") != std::string::npos) {
        p.detail += " isolate=";
        p.detail += g_iso_snap;
        auto pos = g_iso_snap.find("tracer=");
        int iso_t = atoi(g_iso_snap.c_str() + pos + 7);
        if (iso_t > 0) p.hit = true;
    }
    return p;
}

#if defined(__aarch64__)
static void icache_emit(uint32_t* code, uint32_t imm) {
    // add x0, x0, #imm ; ret
    code[0] = 0x91000000u | ((imm & 0xfffu) << 10);
    code[1] = 0xD65F03C0u;
}

static void icache_sync(void* page) {
    __builtin___clear_cache((char*)page, (char*)page + 8);
    asm volatile("isb" ::: "memory");
}
#endif

#if defined(__aarch64__)
// emuck (sitril/xtool emuck): fork + I/D-cache SMC. Real Harvard returns 10.
// Child crash (TCG/unidbg) becomes exit 50/109/111 instead of killing the app.
static int emuck_smc_once() {
    void* page = mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return 255;
    auto* code = (uint32_t*)page;
    using addfn = long (*)(long);
    icache_emit(code, 1);
    icache_sync(page);
    long r1 = ((addfn)page)(0);
    icache_emit(code, 100);
    long r2 = ((addfn)page)(0);
    icache_sync(page);
    long r3 = ((addfn)page)(0);
    munmap(page, 4096);
    if (r1 == 1 && r2 == 1 && r3 == 100) return 10;
    if (r1 == 1 && r2 == 100 && r3 == 100) return 1;
    return 2;
}

static void emuck_on_sig(int sig) {
    if (sig == SIGILL) _exit(109);
    if (sig == SIGSEGV) _exit(111);
    if (sig == SIGBUS) _exit(107);
    if (sig == SIGTRAP) _exit(105);
    if (sig == SIGABRT) _exit(106);
    _exit(50);
}

static int emuck_fork_check() {
    if ((getuid() % 100000) >= 90000) return -2;
    pid_t pid = fork();
    if (pid < 0) return 33;
    if (pid == 0) {
        signal(SIGILL, emuck_on_sig);
        signal(SIGSEGV, emuck_on_sig);
        signal(SIGBUS, emuck_on_sig);
        signal(SIGTRAP, emuck_on_sig);
        signal(SIGABRT, emuck_on_sig);
        _exit(emuck_smc_once());
    }
    int st = 0;
    for (int i = 0; i < 20; i++) {
        if (waitpid(pid, &st, WNOHANG) == pid) break;
        usleep(50000);
        if (i == 19) {
            kill(pid, SIGKILL);
            waitpid(pid, &st, 0);
            return 44;
        }
    }
    if (WIFSIGNALED(st)) return 50;
    if (WIFEXITED(st)) return WEXITSTATUS(st);
    return 50;
}
#endif

static uint64_t read_midr(bool* got) {
    if (got) *got = false;
    char path[96];
    for (int cpu = 0; cpu < 8; cpu++) {
        snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/regs/identification/midr_el1", cpu);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        char buf[64] = {};
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0) continue;
        if (got) *got = true;
        return strtoull(buf, nullptr, 16);
    }
    return 0;
}

Probe probe_qemu() {
    Probe p;
    auto q = prop("ro.kernel.qemu");
    auto qboot = prop("ro.boot.qemu");
    auto hw = prop("ro.hardware");
    auto fp = prop("ro.build.fingerprint");
    auto prod = prop("ro.product.model");
    auto board = prop("ro.product.board");
    p.hit = q == "1" || qboot == "1" || hw.find("goldfish") != std::string::npos ||
            hw.find("ranchu") != std::string::npos || fp.find("generic") != std::string::npos ||
            exists_path("/system/lib/libc_malloc_debug_qemu.so") || exists_path("/init.andy.cloud.rc");
    p.detail = "qemu=" + q + " hw=" + hw;

    static const char* emu_files[] = {
            "/dev/qemu_pipe",
            "/dev/goldfish_pipe",
            "/dev/socket/qemud",
            "/sys/qemu_trace",
            "/dev/socket/genyd",
            "/dev/socket/baseband_genyd",
            "/system/bin/qemu-props",
            "/init.goldfish.rc",
            "/init.ranchu.rc",
            "/sys/bus/platform/drivers/goldfish_pipe",
            "/sys/bus/platform/drivers/goldfish_sync",
            nullptr};
    for (int i = 0; emu_files[i]; i++) {
        if (exists_path(emu_files[i])) {
            p.hit = true;
            p.detail += " ";
            p.detail += emu_files[i];
        }
    }
    auto cpu = read_file("/proc/cpuinfo", 4096);
    if (blob_has_ci(cpu.c_str(), "goldfish") || blob_has_ci(cpu.c_str(), "ranchu") ||
        blob_has_ci(cpu.c_str(), "hypervisor")) {
        p.hit = true;
        p.detail += " cpuinfo-emu";
    }
    if (blob_has_ci(prod.c_str(), "sdk") || blob_has_ci(prod.c_str(), "emulator") ||
        blob_has_ci(board.c_str(), "goldfish") || blob_has_ci(board.c_str(), "ranchu")) {
        p.hit = true;
        p.detail += " model=" + prod;
    }

#if defined(__aarch64__)
    uint64_t ctr = 0;
    asm volatile("mrs %0, ctr_el0" : "=r"(ctr));
    int dic = (int)((ctr >> 29) & 1);
    int idc = (int)((ctr >> 28) & 1);
    void* page = mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        p.detail += " icache=mmap_fail";
        return p;
    }
    auto* code = (uint32_t*)page;
    using addfn = long (*)(long);
    icache_emit(code, 1);
    icache_sync(page);
    long r1 = ((addfn)page)(0);
    icache_emit(code, 100);
    // no I-cache invalidate: real Harvard CPU keeps add#1 in I-cache
    long r2 = ((addfn)page)(0);
    icache_sync(page);
    long r3 = ((addfn)page)(0);

    const int N = 120;
    uint64_t t0 = ticks_now();
    for (int i = 0; i < N; i++) {
        icache_emit(code, (uint32_t)(1 + (i & 1)));
        icache_sync(page);
        ((addfn)page)(0);
    }
    uint64_t t1 = ticks_now();
    uint64_t t2 = ticks_now();
    for (int i = 0; i < N; i++) ((addfn)page)(0);
    uint64_t t3 = ticks_now();
    munmap(page, 4096);
    double smc = (double)(t1 - t0);
    double st = (double)(t3 - t2);
    double smc_ratio = st > 1.0 ? smc / st : 0;

    char buf[220];
    snprintf(buf, sizeof(buf), " DIC=%d IDC=%d r1=%ld r2=%ld r3=%ld smc_ratio=%.1f", dic, idc, r1, r2, r3,
             smc_ratio);
    p.detail += buf;

    bool harvard = (r1 == 1 && r2 == 1 && r3 == 100);
    bool unified = (r1 == 1 && r2 == 100 && r3 == 100);
    // CTR_EL0.DIC=1: hardware I/D already coherent, stale-I-cache test cannot run.
    // Harvard (r2 still 1) proves a real split I/D cache — do not use SMC ratio
    // (icache_sync is expensive on real phones too, ~100x is normal).
    if (harvard) {
        p.detail += " Harvard I/D split";
    } else if (dic == 0 && unified) {
        p.hit = true;
        p.detail += " dcache=ccache (store visible in I-cache without invalidate)";
    } else if (smc_ratio > 80.0 && r1 == 1 && r3 == 100) {
        p.hit = true;
        p.detail += " smc TB-cache slow (qemu/unidbg)";
    }

    int emuck = emuck_fork_check();
    char ebuf[48];
    snprintf(ebuf, sizeof(ebuf), " emuck=%d", emuck);
    p.detail += ebuf;
    // emuck: 10 = real Harvard (libmetasec/emuck convention). Anything else is emu/crash.
    if (emuck >= 0 && emuck != 10 && emuck != -2 && emuck != 33) {
        p.hit = true;
        p.detail += " (emuck SMC not-Harvard)";
    }

    bool midr_got = false;
    uint64_t midr = read_midr(&midr_got);
    unsigned impl = (unsigned)((midr >> 24) & 0xff);
    unsigned part = (unsigned)((midr >> 4) & 0xfff);
    char mbuf[96];
    snprintf(mbuf, sizeof(mbuf), " midr=%s0x%llx impl=0x%x part=0x%x", midr_got ? "" : "na/",
             (unsigned long long)midr, impl, part);
    p.detail += mbuf;
    if (midr_got && midr == 0) {
        p.hit = true;
        p.detail += " (MIDR zero)";
    }
    // HVF-on-Mac leaks host Apple implementer 0x61 into the guest MIDR.
    if (midr_got && impl == 0x61) {
        p.hit = true;
        p.detail += " (Apple MIDR on Android)";
    }

    unsigned long hwcap = getauxval(AT_HWCAP);
    bool aes = (hwcap & HWCAP_AES) != 0;
    p.detail += aes ? " AES=1" : " AES=0";
    // TCG/unidbg often omit AES. Real 64-bit phones since ~2016 have it.
    // Do not hit AES=0 alone on old devices; combine with other emu marks or missing MIDR.
    if (!aes && (q == "1" || hw.find("goldfish") != std::string::npos || midr == 0)) {
        p.hit = true;
        p.detail += " (no AES + emu marks)";
    }

    struct perf_event_attr pe {};
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;
    long cfd = syscall(SYS_perf_event_open, &pe, 0, -1, -1, 0);
    pe.config = PERF_COUNT_HW_INSTRUCTIONS;
    long ifd = syscall(SYS_perf_event_open, &pe, 0, -1, -1, 0);
    if (cfd >= 0 && ifd >= 0) {
        ioctl((int)cfd, PERF_EVENT_IOC_RESET, 0);
        ioctl((int)ifd, PERF_EVENT_IOC_RESET, 0);
        ioctl((int)cfd, PERF_EVENT_IOC_ENABLE, 0);
        ioctl((int)ifd, PERF_EVENT_IOC_ENABLE, 0);
        volatile uint64_t acc = 1;
        for (int i = 0; i < 20000; i++) acc = acc * 6364136223846793005ull + (uint64_t)i;
        ioctl((int)cfd, PERF_EVENT_IOC_DISABLE, 0);
        ioctl((int)ifd, PERF_EVENT_IOC_DISABLE, 0);
        uint64_t cycles = 0, ins = 0;
        read((int)cfd, &cycles, sizeof(cycles));
        read((int)ifd, &ins, sizeof(ins));
        close((int)cfd);
        close((int)ifd);
        double cpi = ins ? (double)cycles / (double)ins : 0;
        char pbuf[64];
        snprintf(pbuf, sizeof(pbuf), " pmc_cpi=%.3f cyc=%llu ins=%llu", cpi, (unsigned long long)cycles,
                 (unsigned long long)ins);
        p.detail += pbuf;
        (void)acc;
        // QEMU software PMU often reports 0 counters.
        if (cycles == 0 && ins == 0) {
            p.hit = true;
            p.detail += " (PMC zero)";
        }
    } else {
        p.detail += " pmc=na";
        if (cfd >= 0) close((int)cfd);
        if (ifd >= 0) close((int)ifd);
    }
#else
    p.detail += " icache=not_arm64";
#endif
    return p;
}

Probe probe_vbmeta() {
    Probe p;
    auto vbs = prop("ro.boot.verifiedbootstate");
    auto vb = prop("ro.boot.vbmeta.device_state");
    auto locked = prop("ro.boot.flash.locked");
    p.hit = vbs == "orange" || vbs == "yellow" || vb == "unlocked" || locked == "0";
    p.detail = "verifiedbootstate=" + vbs + " vbmeta=" + vb + " locked=" + locked;
    return p;
}

Probe probe_magic_mount() {
    Probe p;
    auto mi = read_file("/proc/self/mountinfo");
    int major = 0, minor = 0;
    const char* sp = mi.c_str();
    while (*sp) {
        const char* nl = strchr(sp, '\n');
        size_t n = nl ? (size_t)(nl - sp) : strlen(sp);
        std::string line(sp, n);
        if (line.find(" /data ") != std::string::npos) {
            sscanf(line.c_str(), "%*d %*d %d:%d", &major, &minor);
        }
        if (!nl) break;
        sp = nl + 1;
    }
    if (major == 0 && minor == 0) {
        p.detail = "no /data in mountinfo";
        return p;
    }
    dev_t data = makedev(major, minor);
    auto maps = read_file("/proc/self/maps");
    int count = 0;
    sp = maps.c_str();
    while (*sp) {
        const char* nl = strchr(sp, '\n');
        size_t n = nl ? (size_t)(nl - sp) : strlen(sp);
        std::string line(sp, n);
        if (line.find(" /system/") != std::string::npos || line.find(" /vendor/") != std::string::npos) {
            unsigned f = 0, s = 0;
            if (sscanf(line.c_str(), "%*s %*s %*s %x:%x", &f, &s) >= 2) {
                if (makedev(f, s) == data) count++;
            }
        }
        if (!nl) break;
        sp = nl + 1;
    }
    p.hit = count > 0;
    p.detail = "magic_mount_count=" + std::to_string(count);
    return p;
}

Probe probe_maps_hide() {
    Probe p;
    auto maps = read_file("/proc/self/maps");
    if (maps.empty()) {
        p.detail = "maps unreadable";
        return p;
    }
    int mismatch = 0;
    const char* sp = maps.c_str();
    while (*sp) {
        const char* nl = strchr(sp, '\n');
        size_t n = nl ? (size_t)(nl - sp) : strlen(sp);
        std::string line(sp, n);
        bool interesting = line.find("frida") != std::string::npos ||
                           line.find("magisk") != std::string::npos ||
                           line.find("zygisk") != std::string::npos ||
                           line.find("xposed") != std::string::npos ||
                           line.find("lsposed") != std::string::npos;
        if (interesting && line.find(" /") != std::string::npos) {
            unsigned long start = 0, end = 0;
            if (sscanf(line.c_str(), "%lx-%lx", &start, &end) == 2) {
                char mf[96];
                snprintf(mf, sizeof(mf), "/proc/self/map_files/%lx-%lx", start, end);
                if (faccessat(AT_FDCWD, mf, F_OK, 0) != 0) mismatch++;
            }
        }
        if (!nl) break;
        sp = nl + 1;
    }
    p.hit = mismatch > 8;
    p.detail = "map_files mismatch=" + std::to_string(mismatch);
    return p;
}

Probe probe_mounts() {
    Probe p;
    auto mi = read_file("/proc/self/mountinfo");
    static const char* keys[] = {"magisk", "kernelsu", "apatch", "zygisk", "lspd", "shamiko", nullptr};
    for (int i = 0; keys[i]; i++) {
        if (blob_has_ci(mi.c_str(), keys[i])) {
            p.hit = true;
            if (!p.detail.empty()) p.detail += ',';
            p.detail += keys[i];
        }
    }
    auto init_mi = read_file("/proc/1/mountinfo", 1 << 18);
    if (!init_mi.empty() && init_mi != mi) {
        bool init_has = blob_has_ci(init_mi.c_str(), "magisk") || blob_has_ci(init_mi.c_str(), "debug_ramdisk");
        bool self_has = blob_has_ci(mi.c_str(), "magisk") || blob_has_ci(mi.c_str(), "debug_ramdisk");
        if (init_has && !self_has) {
            p.hit = true;
            p.detail += " init_mnt_has_magisk_self_unmounted";
        }
    }
    auto self_ns = ns_mnt("/proc/self");
    auto init_ns = ns_mnt("/proc/1");
    if (!self_ns.empty() && !init_ns.empty() && self_ns != init_ns) {
        p.detail += " ns_mnt self=" + self_ns + " init=" + init_ns;
    }
    if (!p.hit) p.detail = p.detail.empty() ? "no magisk/ksu in mountinfo" : p.detail;
    return p;
}

Probe probe_adb() {
    Probe p;
    auto adbd = prop("init.svc.adbd");
    auto usb = prop("sys.usb.config");
    auto power = prop("sys.powerboot.adbd");
    // USB debugging is Settings.Global.adb_enabled, not
    // init.svc.adbd / sys.usb.config (those are on whenever a cable is
    // attached). Find ADBD Powerboot is sys.powerboot.adbd non-empty.
    bool settings_adb = g_java_pkgs.find("settings_adb=1") != std::string::npos;
    // USB debugging is a SettingsProvider card. On Flyme it
    // skipped that probe (no USB card) even when adb_enabled=1. Cable
    // init.svc.adbd / sys.usb.config is not their signal. The matching
    // native mark is sys.powerboot.adbd (Find ADBD Powerboot).
    p.hit = !power.empty();
    p.detail = "adbd=" + adbd + " usb=" + usb;
    p.detail += settings_adb ? " settings_adb=1" : " settings_adb=0";
    if (!power.empty()) {
        p.detail += " sys.powerboot.adbd=";
        p.detail += power;
    }
    return p;
}

Probe probe_debuggable() {
    Probe p;
    auto d = prop("ro.debuggable");
    p.hit = d == "1";
    p.detail = "ro.debuggable=" + d;
    return p;
}

Probe probe_testkeys() {
    Probe p;
    auto tags = prop("ro.build.tags");
    auto type = prop("ro.build.type");
    p.hit = tags.find("test-keys") != std::string::npos || type == "userdebug" || type == "eng";
    p.detail = "tags=" + tags + " type=" + type;
    return p;
}

Probe probe_dual_user() {
    Probe p;
    auto maps = read_file("/proc/self/maps");
    p.hit = maps.find("/data/user/") != std::string::npos && maps.find("/data/user/0/") == std::string::npos;
    p.detail = p.hit ? "maps has /data/user/N n!=0" : "single user maps";
    return p;
}

Probe probe_lspd() {
    static const char* xs[] = {"/data/adb/lspd", "/sbin/.magisk/modules/zygisk_lsposed",
                               "/debug_ramdisk/.magisk/modules/zygisk_lsposed", nullptr};
    auto p = from_paths(xs);
    auto mods = modules_matching("lsposed");
    if (!mods.empty()) {
        p.hit = true;
        p.detail += '\n';
        p.detail += mods;
    }
    auto maps = read_file("/proc/self/maps");
    auto mi = read_file("/proc/self/mountinfo");
    auto ux = read_file("/proc/net/unix");
    if (blob_has_ci(maps.c_str(), "lspd") || blob_has_ci(maps.c_str(), "lsposed") ||
        blob_has_ci(maps.c_str(), "LSPHooker")) {
        p.hit = true;
        p.detail += "\nmaps lspd";
    }
    if (blob_has_ci(mi.c_str(), "lspd") || blob_has_ci(ux.c_str(), "lspd")) {
        p.hit = true;
        p.detail += "\nmount/unix lspd";
    }
    if (maps.find("liblsplant") != std::string::npos) {
        p.hit = true;
        p.detail += "\nmaps liblsplant";
    }
    if (g_cls_lsp || g_pkg_lsp) {
        p.hit = true;
        p.detail += "\nFindClass/pkg LSPosed";
    }
    // xposedminversion on a third-party APK is an Xposed *module* marker
    // (probe_xposed), not proof the LSPosed framework is loaded.
    if (g_stack_lsp || g_cl_lsp || g_dex_lsp) {
        p.hit = true;
        p.detail += "\nstack/cl/dex LSPosed";
    }
    if (phdr_has("lspd") || phdr_has("lsplant") || phdr_has("liblsplant")) {
        p.hit = true;
        p.detail += "\ndl_iterate_phdr lspd";
    }
    const char* leaks[] = {"lspd", "lsposed", "lsplant", nullptr};
    auto leak = leak_hits(leaks);
    if (!leak.empty()) {
        p.hit = true;
        p.detail += "\nleak " + leak;
    }
    if (!g_iso_snap.empty() && snap_field(g_iso_snap, "maps_lsp") == 1) {
        p.hit = true;
        p.detail += "\nisolate maps_lsp";
    }
    if (!p.hit) p.detail = "no lspd";
    return p;
}
Probe probe_riru() {
    static const char* xs[] = {"/data/misc/riru/modules/edxp", "/data/misc/riru/modules/dreamland",
                               "/sbin/.magisk/modules/riru_lsposed", "/data/adb/riru/modules/edxp.prop",
                               "/data/adb/riru/modules/dreamland", nullptr};
    auto p = from_paths(xs);
    auto mods = modules_matching("riru");
    if (!mods.empty()) {
        p.hit = true;
        p.detail += '\n';
        p.detail += mods;
    }
    auto maps = read_file("/proc/self/maps");
    if (blob_has_ci(maps.c_str(), "libriru") || blob_has_ci(maps.c_str(), "riru")) {
        p.hit = true;
        p.detail += "\nmaps riru";
    }
    if (!p.hit) p.detail = "no riru";
    return p;
}
static TickStat bench_faccess_svc(const char* path, int n) {
    uint64_t v[48];
    int m = n > 48 ? 48 : n;
    for (int i = 0; i < m; i++) {
        uint64_t a = ticks_now();
        svc5(SYS_faccessat, AT_FDCWD, (long)path, F_OK, 0, 0);
        uint64_t b = ticks_now();
        v[i] = b - a;
    }
    return ticks_stat(v, m, 4);
}

static TickStat bench_faccess_libc(const char* path, int n) {
    uint64_t v[48];
    int m = n > 48 ? 48 : n;
    for (int i = 0; i < m; i++) {
        uint64_t a = ticks_now();
        faccessat(AT_FDCWD, path, F_OK, 0);
        uint64_t b = ticks_now();
        v[i] = b - a;
    }
    return ticks_stat(v, m, 4);
}

static TickStat bench_fstatat_svc(const char* path, int n) {
    uint64_t v[48];
    int m = n > 48 ? 48 : n;
    struct stat st {};
    for (int i = 0; i < m; i++) {
        uint64_t a = ticks_now();
        svc5(SYS_newfstatat, AT_FDCWD, (long)path, (long)&st, 0, 0);
        uint64_t b = ticks_now();
        v[i] = b - a;
    }
    return ticks_stat(v, m, 4);
}

static bool timing_hooked(const TickStat& hidden, const TickStat& gone) {
    if (hidden.avg <= 0 || gone.avg <= 0) return false;
    if (hidden.dev * 10 > hidden.avg || gone.dev * 10 > gone.avg) return false;
    if (hidden.avg < gone.avg * 0.55) return true;  // fake ENOENT, no VFS walk
    if (hidden.avg > gone.avg * 2.2) return true;   // extra hide work
    return false;
}

Probe probe_shamiko() {
    // open /debug_ramdisk/shamiko/module.prop + zygisk_shamiko module id.
    // Principle: multi-channel file visibility (libc faccessat / raw syscall / stat / open),
    // debug_ramdisk listing, module.prop identity (folder can be renamed), maps/mount/unix.
    Probe p;
    std::string ev;
    const char* files[] = {
            "/debug_ramdisk/shamiko/module.prop",
            "/debug_ramdisk/shamiko",
            "/data/adb/shamiko",
            "/data/adb/shamiko/whitelist",
            "/data/adb/modules/zygisk_shamiko",
            "/data/adb/modules/zygisk_shamiko/module.prop",
            "/data/adb/modules/shamiko",
            "/data/adb/modules/shamiko/module.prop",
            "/sbin/.magisk/modules/zygisk_shamiko",
            "/debug_ramdisk/.magisk/modules/zygisk_shamiko",
            nullptr};
    int path_hits = 0;
    for (int i = 0; files[i]; i++) {
        if (path_visible(files[i])) {
            path_hits++;
            ev += files[i];
            ev += '\n';
        }
    }
    int dr_n = 0;
    DIR* dr = opendir("/debug_ramdisk");
    if (dr) {
        while (auto* e = readdir(dr)) {
            if (e->d_name[0] == '.') continue;
            dr_n++;
            if (blob_has_ci(e->d_name, "shamiko")) {
                path_hits++;
                ev += "/debug_ramdisk/";
                ev += e->d_name;
                ev += '\n';
            }
        }
        closedir(dr);
    }
    auto mods = modules_matching("shamiko");
    if (!mods.empty()) {
        ev += mods;
        ev += '\n';
    }
    auto maps = read_file("/proc/self/maps");
    auto mi = read_file("/proc/self/mountinfo");
    auto mnt = read_file("/proc/self/mounts");
    auto ux = read_file("/proc/net/unix");
    bool in_maps = blob_has_ci(maps.c_str(), "shamiko") || blob_has_ci(maps.c_str(), "zygisk_shamiko");
    bool in_mnt = blob_has_ci(mi.c_str(), "shamiko") || blob_has_ci(mnt.c_str(), "shamiko");
    bool in_ux = blob_has_ci(ux.c_str(), "shamiko");
    if (in_maps) ev += "maps shamiko\n";
    if (in_mnt) ev += "mount shamiko\n";
    if (in_ux) ev += "unix shamiko\n";
    auto adb = inspect_adb();
    auto sha = observe_path("/data/adb/shamiko");
    bool libc_sys_diverge = obs_diverge(adb.adb) || (adb.searchable && obs_diverge(sha));
    bool hidden_adb = child_denied(sha, adb.searchable);
    auto init_mi = read_file("/proc/1/mountinfo", 1 << 18);
    auto self_mi = mi;
    bool ns_unmount = !init_mi.empty() &&
                      (blob_has_ci(init_mi.c_str(), "magisk") || blob_has_ci(init_mi.c_str(), "debug_ramdisk") ||
                       blob_has_ci(init_mi.c_str(), "shamiko")) &&
                      !blob_has_ci(self_mi.c_str(), "magisk") && !blob_has_ci(self_mi.c_str(), "shamiko");
    bool iso_unmount = false;
    if (!g_iso_snap.empty() && g_iso_snap.find("timeout") == std::string::npos &&
        g_iso_snap.find("bind_fail") == std::string::npos) {
        int iso_adb_svc = snap_field(g_iso_snap, "adb_svc");
        if (snap_field(g_iso_snap, "shamiko") == 1 && path_hits == 0) {
            iso_unmount = true;
            ev += "isolate sees shamiko, main does not\n";
        } else if ((iso_adb_svc == 0 || snap_field(g_iso_snap, "mods") == 1) && path_hits == 0 &&
                   !adb.present && (in_ux || !mods.empty() || g_pkg_ksu || g_pkg_magisk)) {
            iso_unmount = true;
            ev += "isolate sees /data/adb, main unmounted (hide/denylist)\n";
        }
    }
    if (libc_sys_diverge) ev += "faccessat libc/svc diverge (hook)\n";
    if (hidden_adb) ev += "/data/adb/shamiko EACCES (parent searchable)\n";
    if (ns_unmount) ev += "init mountinfo has magisk, self unmounted (denylist/Shamiko)\n";

    // Shamiko/hide sidechannel: time SVC faccessat/newfstatat.
    // Real ENOENT walks dentry; a hide hook that returns -ENOENT early is faster,
    // a hook that string-matches first is slower. Same errno + different cost = hook.
    const int TN = 20;
    auto t_exist = bench_faccess_svc("/system/bin/sh", TN);
    auto t_gone = bench_faccess_svc("/system/bin/__icheck_absent_7e9c", TN);
    auto t_su = bench_faccess_svc("/system/bin/su", TN);
    auto t_sux = bench_faccess_svc("/system/xbin/su", TN);
    auto t_gone_x = bench_faccess_svc("/system/xbin/__icheck_absent_7e9c", TN);
    auto t_mod = bench_faccess_svc("/debug_ramdisk/shamiko/module.prop", TN);
    auto t_gone_dr = bench_faccess_svc("/debug_ramdisk/__icheck_absent_7e9c", TN);
    auto t_su_st = bench_fstatat_svc("/system/bin/su", TN);
    auto t_gone_st = bench_fstatat_svc("/system/bin/__icheck_absent_7e9c", TN);
    auto t_su_libc = bench_faccess_libc("/system/bin/su", TN);
    bool sc_fast = timing_hooked(t_su, t_gone) || timing_hooked(t_sux, t_gone_x) ||
                   timing_hooked(t_mod, t_gone_dr) || timing_hooked(t_su_st, t_gone_st);
    bool sc_libc = t_su_libc.avg > 0 && t_su.avg > 0 && t_su_libc.avg > t_su.avg * 3.0 &&
                   t_su_libc.dev * 10 <= t_su_libc.avg;
    if (sc_fast) {
        ev += "syscall timing: hidden ENOENT != real ENOENT (hide hook)\n";
    }
    if (sc_libc) ev += "libc faccessat slower than SVC on su (userspace hook)\n";
    char tbuf[280];
    snprintf(tbuf, sizeof(tbuf),
             "sc exist=%.0f gone=%.0f su=%.0f sux=%.0f dr=%.0f su_stat=%.0f su_libc=%.0f",
             t_exist.avg, t_gone.avg, t_su.avg, t_sux.avg, t_mod.avg, t_su_st.avg, t_su_libc.avg);
    ev += tbuf;
    ev += '\n';

    p.hit = path_hits > 0 || !mods.empty() || in_maps || in_mnt || in_ux || libc_sys_diverge ||
            hidden_adb || ns_unmount || iso_unmount || sc_fast || sc_libc;
    if (!p.hit) {
        char buf[420];
        snprintf(buf, sizeof(buf),
                 "no shamiko path=0 modules=0 maps=0 mount=0 unix=0 debug_ramdisk_ents=%d "
                 "adb_libc=%d/%d adb_svc=%d/%d %s",
                 dr_n, adb.adb.libc_rc, adb.adb.libc_err, adb.adb.svc_rc, adb.adb.svc_err, tbuf);
        p.detail = buf;
    } else {
        p.detail = ev;
    }
    return p;
}
Probe probe_vpn() {
    Probe p;
    if (exists_path("/sys/class/net/tun0")) {
        p.hit = true;
        p.detail += "tun0 ";
    }
    if (exists_path("/sys/class/net/ppp0")) {
        p.hit = true;
        p.detail += "ppp0 ";
    }
    DIR* d = opendir("/sys/class/net");
    if (d) {
        while (auto* e = readdir(d)) {
            if (strncmp(e->d_name, "tun", 3) == 0 || strncmp(e->d_name, "ppp", 3) == 0) {
                p.hit = true;
                if (p.detail.find(e->d_name) == std::string::npos) {
                    p.detail += e->d_name;
                    p.detail += ' ';
                }
            }
        }
        closedir(d);
    }
    if (!p.hit) p.detail = "no tun/ppp";
    return p;
}

Probe probe_libc_maps() {
    Probe p;
    auto maps = read_file("/proc/self/maps");
    if (maps.empty()) {
        p.hit = true;
        p.detail = "cannot open maps";
        return p;
    }
    bool found = false;
    const char* sp = maps.c_str();
    while (*sp) {
        const char* nl = strchr(sp, '\n');
        size_t n = nl ? (size_t)(nl - sp) : strlen(sp);
        std::string line(sp, n);
        if (line.find("libc.so") != std::string::npos) {
            found = true;
            if (line.find("---p") != std::string::npos) {
                p.hit = true;
                p.detail = "non-readable libc: " + line;
            }
        }
        if (!nl) break;
        sp = nl + 1;
    }
    if (!found) {
        p.hit = true;
        p.detail = "libc.so absent from maps";
    } else if (!p.hit) {
        p.detail = "libc.so readable";
    }
    return p;
}

Probe probe_uname() {
    Probe p;
    struct utsname u {};
    uname(&u);
    auto os = read_file("/proc/sys/kernel/osrelease");
    while (!os.empty() && (os.back() == '\n' || os.back() == '\r')) os.pop_back();
    p.hit = !os.empty() && os != u.release;
    p.detail = std::string("uname=") + u.release + " osrelease=" + os;
    return p;
}

std::string cpu_info() {
    auto t = read_file("/proc/cpuinfo", 4096);
    if (t.size() > 400) t.resize(400);
    return t.empty() ? "cpuinfo empty" : t;
}

std::string lib_base_info() {
    auto maps = read_file("/proc/self/maps", 1 << 18);
    std::string out;
    for (auto* key : {"libc.so", "libart.so", "linker64"}) {
        auto pos = maps.find(key);
        if (pos != std::string::npos) {
            auto line_start = maps.rfind('\n', pos);
            line_start = line_start == std::string::npos ? 0 : line_start + 1;
            auto line_end = maps.find('\n', pos);
            out += maps.substr(line_start, line_end - line_start);
            out += '\n';
        }
    }
    if (out.empty()) out = "no matching maps";
    return out;
}

std::string fingerprint_prop() {
    return prop("ro.build.fingerprint") + " " + prop("ro.build.version.release");
}

Probe probe_fingerprint() {
    Probe p;
    p.hit = false;
    p.detail = fingerprint_prop() + "\n" + cpu_info();
    return p;
}

std::string md5_hex(const std::string& s) {
    // RFC 1321 MD5, 32 lowercase hex. Used by NativeEngine.MD5.
    static const uint32_t K[64] = {
            0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
            0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
            0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
            0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
            0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
            0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
            0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
            0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};
    static const uint32_t S[64] = {
            7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
            5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
            4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
            6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};
    auto rotl = [](uint32_t x, uint32_t n) { return (x << n) | (x >> (32 - n)); };
    uint64_t bitlen = (uint64_t)s.size() * 8;
    std::string msg(s);
    msg.push_back((char)0x80);
    while ((msg.size() % 64) != 56) msg.push_back(0);
    for (int i = 0; i < 8; i++) msg.push_back((char)((bitlen >> (8 * i)) & 0xff));
    uint32_t a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    for (size_t off = 0; off < msg.size(); off += 64) {
        uint32_t M[16];
        for (int i = 0; i < 16; i++) {
            const unsigned char* p = (const unsigned char*)msg.data() + off + i * 4;
            M[i] = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
        }
        uint32_t A = a0, B = b0, C = c0, D = d0;
        for (uint32_t i = 0; i < 64; i++) {
            uint32_t F, g;
            if (i < 16) { F = (B & C) | ((~B) & D); g = i; }
            else if (i < 32) { F = (D & B) | ((~D) & C); g = (5 * i + 1) % 16; }
            else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
            else { F = C ^ (B | (~D)); g = (7 * i) % 16; }
            F = F + A + K[i] + M[g];
            A = D; D = C; C = B; B = B + rotl(F, S[i]);
        }
        a0 += A; b0 += B; c0 += C; d0 += D;
    }
    char out[33];
    auto byte = [&](uint32_t x, int i) { return (x >> (8 * i)) & 0xff; };
    snprintf(out, sizeof(out),
             "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             byte(a0,0),byte(a0,1),byte(a0,2),byte(a0,3),
             byte(b0,0),byte(b0,1),byte(b0,2),byte(b0,3),
             byte(c0,0),byte(c0,1),byte(c0,2),byte(c0,3),
             byte(d0,0),byte(d0,1),byte(d0,2),byte(d0,3));
    return out;
}

std::string popen_str(const char* cmd) {
    if (!cmd || !*cmd) return "popen fail";
    // Isolated processes (uid % 100000 >= 90000) cannot fork/exec sh.
    if ((getuid() % 100000) >= 90000) return "popen skip isolate";
    FILE* fp = popen(cmd, "r");
    if (!fp) return "popen fail";
    std::string o;
    char buf[256];
    while (fgets(buf, sizeof(buf), fp)) {
        o += buf;
        if (o.size() > 2048) break;
    }
    pclose(fp);
    if (o.empty()) o = "(empty)";
    return o;
}

