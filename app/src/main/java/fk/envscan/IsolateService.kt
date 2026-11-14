package fk.envscan

import android.app.Service
import android.content.Intent
import android.os.IBinder

/**
 * Service running in a separate process. The same crc check runs once per process
 * and the three byte sums are compared with each other (crc_locality).
 *
 * :iso uses android:isolatedProcess="true" and runs in the isolated_app domain, which
 * is what selinux_iso needs for a meaningful comparison.
 * onCreate raises NoNewPrivs to 1: an AMS-spawned isolatedProcess starts at 0 while a
 * standard isolated process has 1, and without it the check flags our own process.
 */
open class ProbeService : Service() {
    private val binder = object : IIsolate.Stub() {
        override fun snapshot(): String = NativeBridge.nativeIsoSnapshot()
        override fun tracerPid(): Int = NativeBridge.nativeTracerPid()
        override fun crcBlob(): String = NativeBridge.nativeCrcBlob()
        override fun ppid(): Int = android.system.Os.getppid()
        override fun selfMaps(): String =
            runCatching { java.io.File("/proc/self/maps").readText().take(1 shl 20) }.getOrDefault("")
        override fun selfCtx(): String =
            runCatching { java.io.File("/proc/self/attr/current").readText().trim() }.getOrDefault("")
    }

    override fun onCreate() {
        super.onCreate()
        runCatching { NativeBridge.nativeHardenIsolate() }
    }

    override fun onBind(intent: Intent?): IBinder = binder
}

class IsolateService : ProbeService()

class TwinService : ProbeService()

/**
 * isolatedProcess + useAppZygote。
 * Binding it makes the system fork this app's app zygote (<pkg>_zygote, app_zygote
 * domain, same app uid). A child of that zygote inherits the zygote's address space,
 * so libraries injected into the zygote show up there — exactly what the
 * "zygote behaviour abnormal / injected" checks need.
 */
class ZygoteProbeService : ProbeService()
