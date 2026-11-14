// EnvScan native front-end.
//
// The detection techniques live in app/src/main/cpp/probes/ (a plain C++
// library with no Android dependencies).  This file is only a thin JNI adapter
// over that library, so the same probe code can be reused by other hosts.

#include <jni.h>
#include <sys/prctl.h>

#include <cstdio>
#include <string>
#include <vector>

#include "probes.h"

namespace {

bool utf8_seq(const std::string& s, size_t i, size_t* len) {
    unsigned char c = static_cast<unsigned char>(s[i]);
    if (c < 0x80) { *len = 1; return true; }
    size_t n = 0;
    if ((c & 0xE0) == 0xC0) n = 2;
    else if ((c & 0xF0) == 0xE0) n = 3;
    else if ((c & 0xF8) == 0xF0) n = 4;
    else return false;
    if (i + n > s.size()) return false;
    for (size_t k = 1; k < n; k++) {
        if ((static_cast<unsigned char>(s[i + k]) & 0xC0) != 0x80) return false;
    }
    *len = n;
    return true;
}

std::string escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (size_t i = 0; i < s.size();) {
        size_t n = 0;
        if (!utf8_seq(s, i, &n)) {
            o += '?';
            i++;
            continue;
        }
        if (n > 1) {
            o.append(s, i, n);
            i += n;
            continue;
        }
        char c = s[i++];
        switch (c) {
            case '\\': o += "\\\\"; break;
            case '"': o += "\\\""; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    o += buf;
                } else {
                    o += c;
                }
        }
    }
    return o;
}

std::string item_json(const char* id, const char* title, const char* status,
                      const std::string& detail) {
    std::string o = "{\"id\":\"";
    o += escape(id);
    o += "\",\"title\":\"";
    o += escape(title);
    o += "\",\"status\":\"";
    o += status;
    o += "\",\"detail\":\"";
    o += escape(detail);
    o += "\"}";
    return o;
}

std::string run_all() {
    int n = 0;
    const NamedTech* rows = all_techniques(&n);
    std::string o = "{\"items\":[";
    for (int i = 0; i < n; i++) {
        if (i) o += ',';
        Probe p = rows[i].fn();
        const std::string id = rows[i].id;
        // :iso runs as android:isolatedProcess="true"; when it reports an isolated_app
        // domain the probe verdict is used, and only a missing process becomes NA.
        if (id == "selinux_iso") {
            const bool no_iso = p.detail.find("isolate se=-") != std::string::npos ||
                                p.detail.find("bind_fail") != std::string::npos;
            // Any other violation (wrong domain / uid outside the isolated range / su context /
            // seccomp=0) still counts as FAIL.
            const bool other_violation =
                p.detail.find("isolate secontext is not isolated_app") != std::string::npos ||
                p.detail.find("isolate uid not in isolated range") != std::string::npos ||
                p.detail.find("twin isolated_app with illegal uid") != std::string::npos ||
                p.detail.find("twin/isolate Seccomp=0") != std::string::npos ||
                p.detail.find("secontext su") != std::string::npos;
            // NoNewPrivs: processes forked from the app zygote inherit NNP=1, while :iso is
            // spawned by AMS and does not. For our own process this is a note, not a violation.
            const bool nnp_only =
                p.detail.find("isolate NoNewPrivs=0") != std::string::npos && !other_violation;
            if (no_iso) {
                p.detail += "\n[EnvScan] :iso did not start; no isolated domain to compare";
                o += item_json(rows[i].id, rows[i].title, "NA", p.detail);
            } else if (nnp_only) {
                p.detail += "\n[EnvScan] :iso is spawned by AMS, so NoNewPrivs is not inherited; reported as a note";
                o += item_json(rows[i].id, rows[i].title, "PASS", p.detail);
            } else {
                o += item_json(rows[i].id, rows[i].title, p.hit ? "FAIL" : "PASS", p.detail);
            }
            continue;
        }
        // An empty iso/twin snapshot must not count as PASS: the other side really ran the
        // crc check and we simply have no data. Report NA instead of "no evidence = pass".
        const bool crc_channel_empty =
            (id == "iso_crc" || id == "twin_crc" || id == "crc_locality") &&
            (p.detail.find("unavailable: empty") != std::string::npos ||
             p.detail.find("Location CRC map is empty") != std::string::npos);
        if (crc_channel_empty) {
            p.detail += "\n[EnvScan] iso/twin snapshot empty; that side of the crc was not compared";
            o += item_json(rows[i].id, rows[i].title, "NA", p.detail);
            continue;
        }
        o += item_json(rows[i].id, rows[i].title, p.hit ? "FAIL" : "PASS", p.detail);
    }
    o += "]}";
    return o;
}

std::string jstr(JNIEnv* env, jstring s) {
    if (!s) return {};
    const char* c = env->GetStringUTFChars(s, nullptr);
    std::string out = c ? c : "";
    if (c) env->ReleaseStringUTFChars(s, c);
    return out;
}

}  // namespace

extern "C" JNIEXPORT jbyteArray JNICALL
Java_fk_envscan_NativeBridge_nativeScan(JNIEnv* env, jclass) {
    // Return bytes, not a JNI string: probe details are derived from /proc and
    // may contain non-UTF-8 bytes. NewStringUTF would truncate the JSON at the
    // first invalid byte (seen as "Unterminated object" in the app).
    std::string json = run_all();
    jbyteArray out = env->NewByteArray(static_cast<jsize>(json.size()));
    if (!out) return nullptr;
    env->SetByteArrayRegion(out, 0, static_cast<jsize>(json.size()),
                            reinterpret_cast<const jbyte*>(json.data()));
    return out;
}

extern "C" JNIEXPORT jint JNICALL
Java_fk_envscan_NativeBridge_nativeTracerPid(JNIEnv*, jclass) {
    return tracer_pid();
}

extern "C" JNIEXPORT jstring JNICALL
Java_fk_envscan_NativeBridge_nativeIsoSnapshot(JNIEnv* env, jclass) {
    return env->NewStringUTF(iso_snapshot().c_str());
}

// Run the crc check inside the :iso / :twin processes and return it to the main process.
extern "C" JNIEXPORT jstring JNICALL
Java_fk_envscan_NativeBridge_nativeCrcBlob(JNIEnv* env, jclass) {
    return env->NewStringUTF(crc_report().c_str());
}

// AMS-spawned isolatedProcess starts with NoNewPrivs=0 while a standard isolated
// process has 1. Set it, otherwise selinux_iso flags our own process as broken.
extern "C" JNIEXPORT void JNICALL
Java_fk_envscan_NativeBridge_nativeHardenIsolate(JNIEnv*, jclass) {
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
}

extern "C" JNIEXPORT void JNICALL
Java_fk_envscan_NativeBridge_nativeSetProcCrc(JNIEnv* env, jclass, jstring iso, jstring twin) {
    set_proc_crc(jstr(env, iso), jstr(env, twin));
}

extern "C" JNIEXPORT void JNICALL
Java_fk_envscan_NativeBridge_nativeSetIsolateSnap(JNIEnv* env, jclass, jstring snap) {
    set_isolate_snap(jstr(env, snap));
}

extern "C" JNIEXPORT void JNICALL
Java_fk_envscan_NativeBridge_nativeSetJavaFindings(
        JNIEnv* env, jclass,
        jboolean xposed_cls, jboolean lsposed_cls,
        jboolean magisk_pkg, jboolean ksu_pkg, jboolean lsp_pkg,
        jboolean stack_lsp, jboolean cl_lsp, jboolean dex_lsp, jboolean xp_meta,
        jstring pkgs) {
    set_java_findings(xposed_cls, lsposed_cls, magisk_pkg, ksu_pkg, lsp_pkg,
                      stack_lsp, cl_lsp, dex_lsp, xp_meta, jstr(env, pkgs));
}

extern "C" JNIEXPORT void JNICALL
Java_fk_envscan_NativeBridge_nativeSetAttest(
        JNIEnv* env, jclass,
        jboolean tee_fail, jboolean aosp, jboolean keybox, jstring detail) {
    set_attest_jni_result(tee_fail, aosp, keybox, jstr(env, detail));
}

jint JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass cls = env->FindClass("fk/envscan/NativeBridge");
    if (!cls) return JNI_ERR;
    static const JNINativeMethod methods[] = {
            {"nativeScan", "()[B",
             reinterpret_cast<void*>(Java_fk_envscan_NativeBridge_nativeScan)},
            {"nativeTracerPid", "()I",
             reinterpret_cast<void*>(Java_fk_envscan_NativeBridge_nativeTracerPid)},
            {"nativeIsoSnapshot", "()Ljava/lang/String;",
             reinterpret_cast<void*>(Java_fk_envscan_NativeBridge_nativeIsoSnapshot)},
            {"nativeCrcBlob", "()Ljava/lang/String;",
             reinterpret_cast<void*>(Java_fk_envscan_NativeBridge_nativeCrcBlob)},
            {"nativeHardenIsolate", "()V",
             reinterpret_cast<void*>(Java_fk_envscan_NativeBridge_nativeHardenIsolate)},
            {"nativeSetProcCrc", "(Ljava/lang/String;Ljava/lang/String;)V",
             reinterpret_cast<void*>(Java_fk_envscan_NativeBridge_nativeSetProcCrc)},
            {"nativeSetIsolateSnap", "(Ljava/lang/String;)V",
             reinterpret_cast<void*>(Java_fk_envscan_NativeBridge_nativeSetIsolateSnap)},
            {"nativeSetJavaFindings", "(ZZZZZZZZZLjava/lang/String;)V",
             reinterpret_cast<void*>(Java_fk_envscan_NativeBridge_nativeSetJavaFindings)},
            {"nativeSetAttest", "(ZZZLjava/lang/String;)V",
             reinterpret_cast<void*>(Java_fk_envscan_NativeBridge_nativeSetAttest)},
    };
    if (env->RegisterNatives(cls, methods, 9) < 0) return JNI_ERR;
    return JNI_VERSION_1_6;
}
