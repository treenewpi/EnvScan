package fk.envscan

import android.app.ZygotePreload
import android.content.pm.ApplicationInfo

/**
 * app zygote 的预加载入口。
 *
 * 系统 fork 出 `<pkg>_zygote` 时会调用它，在 zygote 里把 native 库加载好；
 * 之后 useAppZygote 的 isolated service 就从这里 fork 出来。
 * 这一步是让 EnvScan 拥有一个“同 uid 的 zygote 进程”可检查的前提。
 */
class AppZygote : ZygotePreload {
    override fun doPreload(appInfo: ApplicationInfo) {
        runCatching { System.loadLibrary("envscan") }
    }
}
