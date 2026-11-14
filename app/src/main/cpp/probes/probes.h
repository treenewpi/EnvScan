#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct Probe {
    bool hit = false;
    std::string detail;
};

Probe probe_su();
Probe probe_magisk_files();
Probe probe_magisk_modules();
Probe probe_ksu_apatch();
Probe probe_fingerprint();
Probe probe_zygisk();
Probe probe_xposed();
Probe probe_frida();
Probe probe_selinux();
Probe probe_tracer();
int tracer_pid();
Probe probe_qemu();
Probe probe_vbmeta();
Probe probe_magic_mount();
Probe probe_maps_hide();
Probe probe_mounts();
Probe probe_adb();
Probe probe_debuggable();
Probe probe_testkeys();
Probe probe_dual_user();
Probe probe_lspd();
Probe probe_riru();
Probe probe_shamiko();
Probe probe_vpn();
Probe probe_libc_maps();
Probe probe_uname();
Probe probe_elf_crc();
Probe probe_iso_crc();
Probe probe_twin_crc();
Probe probe_crc_locality();
Probe probe_maps_unread();
Probe probe_unknown_exec();
Probe probe_iso_unknown_exec();
Probe probe_embedded_elf();
Probe probe_odex();
Probe probe_inline_hook();
Probe probe_hwbp();
Probe probe_mmap_legality();
Probe probe_unidbg();
Probe probe_ksu_sidechannel();
Probe probe_avc_log();
Probe probe_solist();
Probe probe_sandbox_stat();
Probe probe_mount_ns();
Probe probe_bind_mount();
Probe probe_resetprop();
std::string mount_ns_pack();
Probe probe_build_identity();
Probe probe_boot_time();
Probe probe_apexd_boot();
Probe probe_ptrace_nspid();
Probe probe_seccomp();
Probe probe_kernel_runtime();
Probe probe_hide_uid();
Probe probe_selinux_isolation();
Probe probe_attestation();
Probe probe_aosp_key();
Probe probe_keybox();
Probe probe_isolate_diff();
Probe probe_zygisk_assistant();
Probe probe_peekaboo();
Probe probe_umount_detach();
Probe probe_dex2oat_mount();
Probe probe_art_method();
Probe probe_prop_serial();
Probe probe_attest_boot();
Probe probe_selinux_oracle();
Probe probe_rom_tamper();
Probe probe_system_server_hook();
Probe probe_tricky_store();
Probe probe_verified_boot();
Probe probe_device_unlock();
Probe probe_others_process();
Probe probe_gwp_asan();
Probe probe_app_launch();
Probe probe_static_integrity();
Probe probe_partition_mount();
Probe probe_procfs_fd();
Probe probe_apk_integrity();
Probe probe_network_trust();
Probe probe_framework_rt();
Probe probe_input_inject();
Probe probe_identity_graph();
uint64_t elf_byte_sum(const uint8_t* p, size_t n);
bool prop_serial_abnormal(uint32_t serial, const char* value);
std::string cpu_info();
std::string lib_base_info();
std::string fingerprint_prop();
std::string sys_prop(const char* key);
std::string md5_hex(const std::string& s);
std::string popen_str(const char* cmd);
std::string elf_text_crc(const char* path);
void set_attest_jni_result(bool tee_fail, bool aosp_software, bool keybox, const std::string& detail);
void set_java_findings(bool xposed_cls, bool lsposed_cls, bool magisk_pkg, bool ksu_pkg, bool lsp_pkg,
                      bool stack_lsp, bool cl_lsp, bool dex_lsp, bool xp_meta,
                      const std::string& pkgs);
void set_isolate_snap(const std::string& snap);
const std::string& isolate_snap();
void set_twin_snap(const std::string& snap);
const std::string& twin_snap();
std::string iso_snapshot();
std::string crc_report();
void set_proc_crc(const std::string& iso, const std::string& twin);
std::string snap_str(const std::string& s, const char* key);
bool path_visible(const char* path);
std::string modules_matching(const char* needle);
bool blob_has_ci(const char* hay, const char* needle);

struct PathObs {
    int libc_rc = -1, libc_err = 0;
    int sys_rc = -1, sys_err = 0;
    int svc_rc = -1, svc_err = 0;
    int stx_rc = -1, stx_err = 0;
};
PathObs observe_path(const char* path);
bool obs_exists(const PathObs& o);
bool obs_denied(const PathObs& o);
bool obs_diverge(const PathObs& o);
bool ksu_ksuctl(int cmd, void* arg1, void* arg2, int32_t* result_out);
long svc5(long nr, long a0, long a1, long a2, long a3, long a4);
int snap_field(const std::string& s, const char* key);
uint64_t ticks_now();
struct TickStat {
    double avg = 0;
    double dev = 0;
    int n = 0;
};
TickStat ticks_stat(const uint64_t* v, int n, int skip);
std::string unix_hits(const char* const* needles);
std::string leak_hits(const char* const* needles);

struct NamedTech {
    const char* id;
    const char* title;
    Probe (*fn)();
};

const NamedTech* all_techniques(int* n);
