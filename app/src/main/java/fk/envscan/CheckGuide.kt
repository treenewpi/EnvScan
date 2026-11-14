package fk.envscan

/**
 * 每个检测项的“人话”说明：检测手法 + 判定原因。
 *
 * method 是这条检查具体读什么、怎么判；reason 根据本次结果给出为什么命中/未命中。
 * native probe 的细粒度手法在源码里，这里给到组级手法 + 关键项的具体手法，避免把
 * 80 条 probe 的实现复制成一份容易过期的文案。
 */
object CheckGuide {

    private val specific = mapOf(
        "su" to "遍历 PATH 与 /system、/sbin、/debug_ramdisk 等固定 su 路径，并区分 EACCES 与 ENOENT。",
        "magisk_files" to "检查 /data/adb、/sbin/.magisk、/debug_ramdisk 与 magisk 模块文件是否可见。",
        "magisk_modules" to "读取 /data/adb/modules 下的 module.prop，识别模块目录与模块身份。",
        "ksu_apatch" to "探测 /data/adb、ap/ksu 目录的 EACCES 错误码，并核对 KernelSU/APatch 管理器包名。",
        "shamiko" to "检查 /debug_ramdisk/shamiko、/data/adb 模块、mountinfo 与 unix socket 里的 Shamiko 痕迹。",
        "zygisk" to "扫描 /proc/self/maps、linker solist 与 LD_PRELOAD，找 libzygisk / zygisk 注入。",
        "xposed" to "检查 /system/xposed.prop、XposedBridge.jar、LSPHooker 与 LSPosed 模块路径。",
        "riru" to "检查 /data/misc/riru 模块目录与 riru 相关映射。",
        "lspd" to "检查 /data/adb/lspd 与 zygisk_lsposed 模块路径。",
        "frida" to "扫描 maps 中的 frida/gadget/linjector、/proc/net/unix、线程名与 27042 端口。",
        "tracer" to "读取 /proc/self/status 的 TracerPid，并与 :iso 进程的快照比对。",
        "maps_hide" to "逐条比对 /proc/self/maps 与 /proc/self/map_files，找被隐藏的 so 映射。",
        "mounts" to "解析 mountinfo，找 magisk/KSU/APatch/lspd 与 data-backed overlay 挂载。",
        "selinux" to "读取 /proc/self/attr/current 与 /sys/fs/selinux/enforce，判断域和 Enforcing 状态。",
        "qemu" to "检查 ro.kernel.qemu、goldfish/ranchu 属性、/dev/qemu_pipe 与云真机文件。",
        "vbmeta" to "读取 verifiedbootstate / vbmeta.device_state / flash.locked，判断解锁与校验状态。",
        "testkeys" to "读取 ro.build.tags 与 ro.build.type，识别 test-keys / userdebug。",
        "debuggable" to "读取 ro.debuggable、ro.secure 与 init.svc.adbd。",
        "elf_crc" to "对 libc/libart/linker64 的可执行段做内存与文件字节和对比，检测 inline hook。",
        "unknown_exec" to "遍历可执行映射，找不在 system/apex/data-app 白名单内的项。",
        "sandbox_stat" to "把 app 沙箱目录的 stat 设备号与 mountinfo 对比，检测 stat/mount 伪装。",
        "resetprop" to "交叉核对 ro.build.*、ro.system.*、vbmeta、serial 与属性区一致性。",
        "prop_serial" to "读取属性区 serial 与值长度，识别 resetprop 留下的 serial 异常。",
        "build_identity" to "比对 fingerprint、tags、kernel version 与 dirty/1970/Toybox 特征。",
        "boot_time" to "用 CLOCK_BOOTTIME、/proc/uptime 与 /proc/stat btime 做三方对时。",
        "ptrace_nspid" to "比对 getpid/getppid/uid 与 /proc/self/status、stat 的 NSpid/PPid。",
        "seccomp" to "用 PR_GET_SECCOMP 与 /proc/self/status 的 Seccomp 字段交叉确认。",
        "attestation" to "生成 AndroidKeyStore 密钥，解析 Key Attestation 链与 TEE 状态。",
        "aosp_key" to "检查 attestation 根证书是否为 AOSP/software attestation。",
        "keybox" to "检查证明链长度与根证书，识别 keybox 替换/短链。",
        "isolate_diff" to "比对主进程与 :iso 进程的 su/模块/SELinux 快照差异。",
        "zygisk_assistant" to "检查 /data/adb/modules/zygisk_assistant 与 Zygisk-Assistant 文件。",
        "peekaboo" to "检查 /data/adb/kpm/cherish_peekaboo.kpm 与相关模块目录。",
        "umount_detach" to "检查 zygisk-detach / ksu_susfs 模块与 mountinfo 里的 umount 痕迹。",
        "dex2oat_mount" to "检查 /data/adb/lspd/dex2oat 与 mountinfo/maps 中的 lspd dex2oat 挂载。",
        "fingerprint" to "采集 Build fingerprint 与 CPU 信息，作为报告基线。",
        "storage.crypto" to "读取 ro.crypto.state / ro.crypto.type，并核对 /data 的 mount 参数。",
        "runtime.art" to "比对 dalvik.vm.heapsize、heapgrowthlimit 与 dex2oat-filter 是否异常。",
        "boot.init_rc" to "读取 /system/etc/init/hw/init.rc，找 magisk/resetprop/insmod 等注入标记。",
        "system.permission" to "检查 SELinux policy 是否存在、policyvers 与 system_file 标签。",
        "root.su_process" to "遍历 /proc/*/cmdline 与 ps，找 su/magisk/ksud/apatch 进程。",
        "zygote.behavior" to "统计 zygote 进程数量，识别多出来的自建 zygote。",
        "zygote.injected" to "尝试读取 zygote 的 maps，找 xposed/zygisk/riru/frida 映射。",
        "notify.bar" to "检查通知监听、悬浮窗与通知策略访问三方状态。",
        "manifest.graph" to "枚举本包 Activity/Service，对比 EnvScan 声明的组件图。",
        "attest.play_integrity" to "用本地 Key Attestation 判定 boot 状态（server 未配置时回退本地）。",
        "selinux.policy_file" to "读取 /sys/fs/selinux/policy、policyvers 与 checkreqprot。",
        "hide.shamiko_missing" to "检测到 root 管理器但找不到 Shamiko 隐藏模块时命中。",
        "boot.bootloader_spoof" to "检查 verifiedbootstate=green 与 locked=0 / digest 为空是否矛盾。",
        "inject.rvx" to "枚举包名，找 rvx/revanced/microg 相关模块。",
        "inject.service" to "枚举包含 inject/zygisk/xposed/lsposed 的包与进程。",
        "hide.zygisk_exclusion" to "检查本进程 maps 是否被 Zygisk/LSPosed 注入，判断排除列表是否生效。",
        "debug.tombstone" to "尝试读取 /data/tombstones 与 /data/anr，找崩溃/注入痕迹。",
        "hide_uid" to "对比 getuid()、/proc/self/status 的 Uid/appid 与 :iso 进程 uid，检测 UID 隐藏或重映射。",
        "iso_unknown_exec" to "在 :iso 进程里重复 unknown_exec 检查，找主进程看不到的可执行映射。",
        "apexd_boot" to "读取 init.svc.apexd、apexd.status 与 CLOCK_BOOTTIME，核对 APEX 启动时间是否被改。",
        "kernel_runtime" to "读取 /proc/version 与 uname，检查 release/version 是否与 libc/内核侧不一致。",
        "sandbox_stat" to "把 app 沙箱目录的 stat 设备号与 mountinfo 对比，检测 stat/mount 伪装。",
        "boot_time" to "用 CLOCK_BOOTTIME、/proc/uptime 与 /proc/stat btime 做三方对时。",
        "rom_tamper" to "比对 Build fingerprint、brand/model 与 vbmeta/内核身份，检测 ROM 伪装。",
        "verified_boot" to "读取 verifiedbootstate、vbmeta.device_state 与 flash.locked，判断解锁/校验状态。",
        "device_unlock" to "检查 ro.boot.flash.locked、vbmeta.device_state 与 TEE 解锁状态。",
        "identity_graph" to "交叉核对 Build 字段、vbmeta、serial 与内核身份是否自相矛盾。",
        "network_trust" to "检查用户 CA、网络安全配置与证书信任锚。",
        "apps.managers" to "枚举常见 root/框架管理器包名，判断是否装了 KSU/APatch/Magisk 管理器。",
        "hide.isolate_tracer" to "对比主进程与 :iso 进程的 TracerPid。",
        "debug.notification_listener" to "读取 Settings.Secure 的 enabled_notification_listeners，找三方通知监听。",
        "debug.accessibility" to "读取 Settings.Secure 的 enabled_accessibility_services。",
        "debug.adb" to "读取 Settings.Global.ADB_ENABLED。",
        "debug.developer" to "读取 Settings.Global.DEVELOPMENT_SETTINGS_ENABLED。",
        "debug.mock_location" to "读取 AppOps 的 mock_location 授权。",
        "net.vpn_java" to "用 ConnectivityManager 查 active transport 与 VPN 网络。",
        "hide.work_profile" to "检查当前 uid/用户目录，判断是否工作资料或非主用户。",
        "apps.pm_ways" to "用 getInstalledPackages、queryIntentActivities、pm list packages 三路交叉枚举。",
        "inject.xposed_pm" to "检查启动器 meta-data 的 xposedminversion，并反射 XposedBridge 类。",
    )

    private val groupMethod = mapOf(
        "Root" to "路径探测 + /data/adb 错误码 + mountinfo 设备号。",
        "Injection" to "maps、linker solist、unix socket、线程名与模块路径。",
        "Hide" to "TracerPid、maps/map_files、主进程与 :iso 的差异。",
        "Integrity" to "ELF 内存/file 校验、procfs、seccomp 与 SELinux。",
        "Identity" to "Build 属性、vbmeta、uname、boot time 与 Key Attestation。",
        "TEE" to "KeyStore 证明链与 attestation 扩展。",
        "Emulator" to "qemu/goldfish 属性、设备节点与云真机文件。",
        "Debug" to "Settings 与系统属性。",
        "Network" to "路由表、网卡与 ConnectivityManager。",
        "Apps" to "PackageManager 多路枚举。",
    )

    fun method(item: ScanItem): String =
        specific[item.id] ?: groupMethod[item.group] ?: "读取系统属性、文件与进程状态。"

    fun reason(item: ScanItem): String {
        val first = item.detail.lineSequence().firstOrNull { it.isNotBlank() }?.trim().orEmpty()
        val evidence = if (first.isEmpty()) "（没有读到证据）" else first
        return when (item.status) {
            Status.FAIL -> "命中风险条件。关键证据：$evidence"
            Status.WARN -> "命中可疑条件，但不足以定级为失败。关键证据：$evidence"
            Status.PASS -> "未命中。本次读取：$evidence"
            Status.NA -> "设备或权限限制，无法完成该检查：$evidence"
        }
    }
}
