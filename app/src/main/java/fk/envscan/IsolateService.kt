package fk.envscan

import android.app.Service
import android.content.Intent
import android.os.IBinder

/**
 * 独立进程的服务进程。同一套 crc 检查在每个进程里各跑一遍，再把三份 bytesum
 * 互相比对（crc_locality）。
 *
 * :iso 用 android:isolatedProcess="true"，跑在 isolated_app 域里，selinux_iso
 * 才有隔离域可比。
 * onCreate 里补 NoNewPrivs=1：AMS 拉起的 isolatedProcess 默认是 0，而标准 isolated
 * 进程是 1，不补就会把自己判成“隔离失效”。
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
 * 绑定它会让系统拉起 app zygote（<pkg>_zygote，跑在 app_zygote 域、同 app uid），
 * 这个 zygote 的子进程地址空间就是 zygote 的，注入 zygote 的库会原样继承过来，
 * 正好用来判断 “zygote 行为异常 / 被注入”。
 */
class ZygoteProbeService : ProbeService()
