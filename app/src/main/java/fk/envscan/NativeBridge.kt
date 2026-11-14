package fk.envscan

object NativeBridge {
    init {
        System.loadLibrary("envscan")
    }

    @JvmStatic
    external fun nativeScan(): ByteArray

    @JvmStatic
    external fun nativeTracerPid(): Int

    @JvmStatic
    external fun nativeIsoSnapshot(): String

    @JvmStatic
    external fun nativeCrcBlob(): String

    @JvmStatic
    external fun nativeHardenIsolate()

    @JvmStatic
    external fun nativeSetProcCrc(iso: String, twin: String)

    @JvmStatic
    external fun nativeSetIsolateSnap(snap: String)

    @JvmStatic
    external fun nativeSetJavaFindings(
        xposedCls: Boolean,
        lsposedCls: Boolean,
        magiskPkg: Boolean,
        ksuPkg: Boolean,
        lspPkg: Boolean,
        stackLsp: Boolean,
        clLsp: Boolean,
        dexLsp: Boolean,
        xpMeta: Boolean,
        pkgs: String,
    )

    @JvmStatic
    external fun nativeSetAttest(teeFail: Boolean, aosp: Boolean, keybox: Boolean, detail: String)
}
