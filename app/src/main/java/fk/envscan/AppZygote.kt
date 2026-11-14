package fk.envscan

import android.app.ZygotePreload
import android.content.pm.ApplicationInfo

/**
 * Preload entry point of the app zygote.
 *
 * The system calls it when forking `<pkg>_zygote`, which loads the native library
 * inside the zygote; the isolated services that use useAppZygote are then forked
 * from there. This is what gives EnvScan a zygote process of its own uid to inspect.
 */
class AppZygote : ZygotePreload {
    override fun doPreload(appInfo: ApplicationInfo) {
        runCatching { System.loadLibrary("envscan") }
    }
}
