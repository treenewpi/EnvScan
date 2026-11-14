package fk.envscan

import android.app.AppOpsManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * EnvScan 的 Java 半边只做两件事：
 *   1. 采集 Java 层能拿到、native 拿不到的事实，喂给 probe 库
 *      （包名 / Xposed 元数据 / KeyStore 证明链）；
 *   2. 展示 probe 库给出的技术项，以及 probe 库不覆盖的 PM 四路 / Settings 项。
 *
 * 检测技术本身不在这里实现：唯一实现是 cpp/probes/，ID 就是 all_techniques() 里的 ID。
 */
object ScanEngine {

    /**
     * app zygote（`<pkg>_zygote`）的 pid。由 useAppZygote 的 isolated service 报回 PPid，
     * 主进程靠它去读同 uid 的 zygote 子进程，用来判断 zygote 是否被注入。
     */
    @Volatile
    var zygotePpid: Int = -1

    /** app-zygote 子进程自己的 maps 与 SELinux 域。 */
    @Volatile
    var zygoteMaps: String = ""

    @Volatile
    var zygoteCtx: String = ""

    private val managerPkgs = listOf(
        "com.topjohnwu.magisk" to "Magisk",
        "io.github.huskydg.magisk" to "Magisk Delta / HuskyDG",
        "io.github.vvb2060.magisk" to "Magisk Alpha",
        "com.nift4.magisk" to "Magisk",
        "me.weishu.kernelsu" to "KernelSU",
        "me.bmax.apatch" to "APatch",
        "org.lsposed.manager" to "LSPosed",
        "org.lsposed.lspatch" to "LSPatch",
        "de.robv.android.xposed.installer" to "Xposed Installer",
        "org.meowcat.edxposed.manager" to "EdXposed",
        "com.solohsu.android.edxp.manager" to "EdXposed",
        "org.lsposed.manager.debug" to "LSPosed debug",
        "com.android.vending.billing.InAppBillingService.COIN" to "Lucky Patcher",
        "eu.faircode.xlua" to "XPrivacyLua",
        "com.saurik.substrate" to "Substrate",
        "com.thirdparty.superuser" to "Superuser",
        "eu.chainfire.supersu" to "SuperSU",
        "com.koushikdutta.superuser" to "Superuser",
        "com.topjohnwu.magisk.canary" to "Magisk Canary",
    )

    private val groupOf: Map<String, String> = buildMap {
        for (id in listOf(
            "su", "magisk_files", "magisk_modules", "ksu_apatch", "shamiko", "magic_mount",
            "mounts", "lspd", "riru", "tricky_store", "partition_mount", "rom_tamper",
            "ksu_sidechannel", "hide_uid",
        )) put(id, "Root")
        for (id in listOf(
            "zygisk", "xposed", "frida", "inline_hook", "art_method", "ss_hook", "solist",
            "others_process", "input_inject", "app_launch", "static_integrity", "apk_integrity",
            "framework_rt",
        )) put(id, "Injection")
        for (id in listOf(
            "tracer", "maps_hide", "isolate_diff", "zygisk_assistant", "peekaboo",
            "umount_detach", "dex2oat_mount", "dual_user", "procfs_fd",
        )) put(id, "Hide")
        for (id in listOf(
            "selinux", "selinux_iso", "selinux_oracle", "elf_crc", "iso_crc", "twin_crc",
            "crc_locality", "maps_unread", "embedded_elf", "odex", "mmap_legality", "hwbp",
            "unidbg", "kernel_runtime", "boot_time", "apexd_boot", "ptrace_nspid", "seccomp",
            "avc_log", "mount_ns", "bind_mount", "gwp_asan", "unknown_exec", "iso_unknown_exec",
        )) put(id, "Integrity")
        for (id in listOf(
            "vbmeta", "testkeys", "uname", "sandbox_stat", "resetprop", "prop_serial",
            "build_identity", "verified_boot", "device_unlock", "attest_boot", "identity_graph",
            "attestation", "aosp_key", "keybox", "fingerprint",
        )) put(id, "Identity")
        put("qemu", "Emulator")
        put("vpn", "Network")
        put("network_trust", "Network")
        put("adb", "Debug")
        put("debuggable", "Debug")
    }

    fun parseNative(json: String, source: String): List<ScanItem> {
        val arr = JSONObject(json).getJSONArray("items")
        val out = ArrayList<ScanItem>(arr.length())
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            val id = o.getString("id")
            out += ScanItem(
                id = id,
                group = o.optString("group").ifBlank { groupOf[id] ?: "Integrity" },
                title = o.getString("title"),
                status = runCatching { Status.valueOf(o.getString("status")) }.getOrDefault(Status.NA),
                detail = o.optString("detail"),
                source = source,
            )
        }
        return out
    }

    /**
     * Java 侧采集 + 喂 probe 库。必须在 nativeScan() 之前调用。
     */
    fun prepare(ctx: Context): List<ScanItem> {
        val hits = managerHits(ctx)
        val xp = xposedFindings(ctx)
        NativeBridge.nativeSetJavaFindings(
            xposedCls = xp.xposedCls,
            lsposedCls = xp.lsposedCls,
            magiskPkg = hits.any { it.first == "com.topjohnwu.magisk" || it.first.contains("magisk") },
            ksuPkg = hits.any { it.first.contains("kernelsu") || it.first.contains("apatch") },
            lspPkg = hits.any { it.first.contains("lsposed") || it.first.contains("xposed") },
            stackLsp = false,
            clLsp = xp.lsposedCls,
            dexLsp = false,
            xpMeta = xp.xpMeta,
            pkgs = hits.joinToString(",") { it.first },
        )
        feedAttestation()

        val items = mutableListOf<ScanItem>()
        items += ScanItem(
            id = "apps.managers",
            group = "Root",
            title = "Root / framework manager packages",
            status = if (hits.isEmpty()) Status.PASS else Status.FAIL,
            detail = if (hits.isEmpty()) "QUERY found no known manager" else hits.joinToString("\n") { "${it.second} (${it.first})" },
            source = "java",
        )
        items += xp.item
        items += scanPmWays(ctx)
        items += scanSettings(ctx)
        items += scanProfile()
        items += ExtraChecks.collect(ctx)
        return items
    }

    private fun managerHits(ctx: Context): List<Pair<String, String>> {
        val pm = ctx.packageManager
        val out = mutableListOf<Pair<String, String>>()
        for ((pkg, label) in managerPkgs) {
            val found = runCatching {
                pm.getPackageInfo(pkg, 0)
                true
            }.getOrDefault(false)
            if (found) out += pkg to label
        }
        return out
    }

    private data class XposedFindings(
        val xposedCls: Boolean,
        val lsposedCls: Boolean,
        val xpMeta: Boolean,
        val pkgs: List<String>,
        val item: ScanItem,
    )

    private fun xposedFindings(ctx: Context): XposedFindings {
        val pm = ctx.packageManager
        val hits = mutableListOf<String>()
        runCatching {
            val list = pm.queryIntentActivities(Intent(Intent.ACTION_MAIN), PackageManager.GET_META_DATA)
            for (ri in list) {
                val ai = ri.activityInfo.applicationInfo
                if (ai.metaData?.containsKey("xposedminversion") == true) {
                    hits += pm.getApplicationLabel(ai).toString() + " (" + ai.packageName + ")"
                }
            }
        }
        val xposedCls = runCatching { Class.forName("de.robv.android.xposed.XposedBridge"); true }.getOrDefault(false)
        val lspCls = runCatching { Class.forName("org.lsposed.lspd.core.Main"); true }.getOrDefault(false)
        return XposedFindings(
            xposedCls = xposedCls,
            lsposedCls = lspCls,
            xpMeta = hits.isNotEmpty(),
            pkgs = hits,
            item = ScanItem(
                id = "inject.xposed_pm",
                group = "Injection",
                title = "Xposed module (launcher meta / class)",
                status = if (hits.isEmpty() && !xposedCls && !lspCls) Status.PASS else Status.FAIL,
                detail = buildString {
                    appendLine("xposedminversion=${hits.ifEmpty { listOf("none") }}")
                    appendLine("XposedBridge=${xposedCls} lspd.Main=${lspCls}")
                    append("meta_hits=${hits.size}")
                },
                source = "java",
            ),
        )
    }

    // ApplistDetector 的 PM 四路：同一包在某一路被藏、另一路可见才是信号。
    private fun scanPmWays(ctx: Context): ScanItem {
        val pm = ctx.packageManager
        val direct = runCatching { pm.getInstalledPackages(0).map { it.packageName }.toSet() }
            .getOrDefault(emptySet())
        val viaIntent = runCatching {
            pm.queryIntentActivities(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0)
                .map { it.activityInfo.packageName }.toSet()
        }.getOrDefault(emptySet())
        val viaShell = runCatching {
            val p = ProcessBuilder("pm", "list", "packages").redirectErrorStream(true).start()
            p.inputStream.bufferedReader().readLines()
                .filter { it.startsWith("package:") }
                .map { it.removePrefix("package:").trim() }
                .toSet()
        }.getOrDefault(emptySet())
        val diffs = mutableListOf<String>()
        for ((pkg, _) in managerPkgs) {
            val a = pkg in direct
            val b = pkg in viaIntent
            val c = pkg in viaShell
            if (a != b || a != c) diffs += "$pkg direct=$a intent=$b shell=$c"
        }
        return ScanItem(
            id = "apps.pm_ways",
            group = "Root",
            title = "PackageManager cross-check",
            status = if (diffs.isEmpty()) Status.PASS else Status.FAIL,
            detail = buildString {
                appendLine("direct=${direct.size} launchable=${viaIntent.size} shell=${viaShell.size}")
                if (diffs.isNotEmpty()) append(diffs.joinToString("\n"))
            }.trim(),
            source = "java",
        )
    }

    private fun scanSettings(ctx: Context): List<ScanItem> {
        val cr = ctx.contentResolver
        val adb = Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0)
        val dev = Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0)
        val mock = runCatching {
            val ops = ctx.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
            ops.checkOpNoThrow(
                AppOpsManager.OPSTR_MOCK_LOCATION,
                android.os.Process.myUid(),
                ctx.packageName,
            ) == AppOpsManager.MODE_ALLOWED
        }.getOrDefault(false)
        val accessibility = Settings.Secure.getString(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: ""
        val listeners = Settings.Secure.getString(cr, "enabled_notification_listeners") ?: ""
        val vpn = runCatching {
            val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val net = cm.activeNetwork ?: return@runCatching false
            val caps = cm.getNetworkCapabilities(net) ?: return@runCatching false
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        }.getOrDefault(false)
        return listOf(
            ScanItem(
                id = "debug.adb", group = "Debug", title = "USB debugging",
                // ADB 是调试开关，不等于 root/篡改；给 WARN，避免正常测试机被判成“风险”。
                status = if (adb == 1) Status.WARN else Status.PASS,
                detail = "Settings.Global.ADB_ENABLED=$adb", source = "java",
            ),
            ScanItem(
                id = "debug.developer", group = "Debug", title = "Developer options",
                status = if (dev == 1) Status.WARN else Status.PASS,
                detail = "DEVELOPMENT_SETTINGS_ENABLED=$dev", source = "java",
            ),
            ScanItem(
                id = "debug.mock_location", group = "Debug", title = "Mock location AppOp",
                status = if (mock) Status.WARN else Status.PASS,
                detail = "OPSTR_MOCK_LOCATION=${if (mock) "ALLOWED" else "denied/default"}",
                source = "java",
            ),
            ScanItem(
                id = "debug.accessibility", group = "Debug", title = "Accessibility services",
                status = if (accessibility.isBlank()) Status.PASS else Status.WARN,
                detail = accessibility.ifBlank { "(empty)" }, source = "java",
            ),
            run {
                val nonSystem = listeners.split(':').filter { it.isNotBlank() }.filter { comp ->
                    val pkg = comp.substringBefore('/')
                    val ai = runCatching { ctx.packageManager.getApplicationInfo(pkg, 0) }.getOrNull()
                    ai != null && (ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) == 0
                }
                ScanItem(
                    id = "debug.notification_listener", group = "Debug", title = "Notification listeners",
                    status = if (nonSystem.isNotEmpty()) Status.WARN else Status.PASS,
                    detail = buildString {
                        appendLine("listeners=${listeners.ifBlank { "(empty)" }}")
                        append("non_system=${nonSystem.ifEmpty { listOf("none") }}")
                    },
                    source = "java",
                )
            },
            ScanItem(
                id = "net.vpn_java", group = "Network", title = "VPN (ConnectivityManager)",
                status = if (vpn) Status.WARN else Status.PASS,
                detail = "active transport VPN=$vpn", source = "java",
            ),
        )
    }

    private fun scanProfile(): ScanItem {
        val uid = android.os.Process.myUid() / 100000
        val dirs = (1..9).mapNotNull { n -> File("/data/user/$n").takeIf { it.exists() }?.path }
        val status = if (uid != 0 || dirs.isNotEmpty()) Status.WARN else Status.PASS
        return ScanItem(
            id = "hide.work_profile", group = "Hide", title = "Work profile / multi-user",
            status = status,
            detail = "myUserId=$uid visible_data_users=$dirs", source = "java",
        )
    }

    // KeyStore 证明链只能在 Java 侧生成，结果喂给 probe_attestation /
    // probe_aosp_key / probe_keybox，由 native 统一出 3 个技术项。
    private fun feedAttestation() {
        runCatching {
            val alias = "envscan-attest"
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (ks.containsAlias(alias)) ks.deleteEntry(alias)
            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            val challenge = UUID.randomUUID().toString().toByteArray()
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)
                .build()
            kpg.initialize(spec)
            kpg.generateKeyPair()
            val chain = ks.getCertificateChain(alias)
            val detail = StringBuilder("chain=")
            if (chain == null || chain.isEmpty()) {
                NativeBridge.nativeSetAttest(true, false, true, "chain empty")
                return@runCatching
            }
            val leaf = chain[0] as X509Certificate
            val root = chain.last() as X509Certificate
            val rootDn = root.subjectDN.name
            detail.append(chain.size).append(" leaf=").append(leaf.subjectDN.name)
            detail.append(" root=").append(rootDn)
            val aosp = rootDn.contains("Android Keystore Software", ignoreCase = true) ||
                rootDn.contains("software", ignoreCase = true)
            val keybox = chain.size < 2
            val ext = leaf.getExtensionValue("1.3.6.1.4.1.11129.2.1.17")
            val rot = ext?.let { parseRootOfTrust(it) }
            detail.append(" rot=").append(rot?.toString() ?: "absent")
            val teeFail = false
            NativeBridge.nativeSetAttest(teeFail, aosp, keybox, detail.toString())
        }.onFailure { e ->
            NativeBridge.nativeSetAttest(true, false, true, "attestation failed: ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    data class RootOfTrust(val verifiedBootState: Int, val deviceLocked: Int, val verifiedBootHash: String)

    fun parseRootOfTrustPublic(ext: ByteArray): RootOfTrust? = parseRootOfTrust(ext)

    private fun parseRootOfTrust(ext: ByteArray): RootOfTrust? {
        val pattern = byteArrayOf(0xBF.toByte(), 0x85.toByte(), 0x40)
        val at = indexOf(ext, pattern)
        if (at < 0 || at + 4 >= ext.size) return null
        var p = at + 3
        var len = ext[p].toInt() and 0xff
        p++
        if (len and 0x80 != 0) {
            val n = len and 0x7f
            len = 0
            for (i in 0 until n) {
                if (p >= ext.size) return null
                len = (len shl 8) or (ext[p].toInt() and 0xff)
                p++
            }
        }
        val end = minOf(ext.size, p + len)
        var vbs = -1
        var locked = -1
        var hash = ""
        while (p + 2 <= end) {
            val tag = ext[p].toInt() and 0xff
            var l = ext[p + 1].toInt() and 0xff
            var q = p + 2
            if (l and 0x80 != 0) {
                val n = l and 0x7f
                l = 0
                for (i in 0 until n) {
                    if (q >= end) return null
                    l = (l shl 8) or (ext[q].toInt() and 0xff)
                    q++
                }
            }
            if (q + l > end) break
            when (tag) {
                0x80 -> if (l == 1) vbs = ext[q].toInt() and 0xff
                0x81 -> if (l == 1) locked = ext[q].toInt() and 0xff
                0x82 -> hash = ext.copyOfRange(q, q + l).joinToString("") { "%02x".format(it) }
            }
            p = q + l
        }
        if (vbs < 0 && locked < 0) return null
        return RootOfTrust(vbs, locked, hash)
    }

    private fun indexOf(hay: ByteArray, needle: ByteArray): Int {
        if (needle.isEmpty() || hay.size < needle.size) return -1
        outer@ for (i in 0..hay.size - needle.size) {
            for (j in needle.indices) {
                if (hay[i + j] != needle[j]) continue@outer
            }
            return i
        }
        return -1
    }

    fun mergeIsolate(tracer: Int): List<ScanItem> = listOf(
        ScanItem(
            id = "hide.isolate_tracer",
            group = "Hide",
            title = "Isolate process TracerPid",
            status = when {
                tracer < 0 -> Status.NA
                tracer > 0 -> Status.FAIL
                else -> Status.PASS
            },
            detail = "isolate TracerPid=$tracer",
            source = "iso",
        ),
    )

    fun writeReport(ctx: Context, report: ScanReport): String? = runCatching {
        val arr = JSONArray()
        for (it in report.items) {
            arr.put(JSONObject().apply {
                put("id", it.id)
                put("group", it.group)
                put("title", it.title)
                put("status", it.status.name)
                put("detail", it.detail)
                put("source", it.source)
            })
        }
        val root = JSONObject().apply {
            put("package", "fk.envscan")
            put("verdict", report.verdict.name.lowercase())
            put("fail", report.fail)
            put("warn", report.warn)
            put("pass", report.pass)
            put("items", arr)
        }
        val dir = ctx.getExternalFilesDir(null) ?: ctx.filesDir
        val f = File(dir, "envscan-report.json")
        f.writeText(root.toString(2))
        f.absolutePath
    }.getOrNull()
}

class IsolateClient(private val ctx: Context) {
    data class Result(
        val snapshot: String?,
        val tracerPid: Int,
        val isoCrc: String?,
        val twinCrc: String?,
        /** app zygote（<pkg>_zygote）的 pid，由 useAppZygote 的 isolated service 报 PPid 得到。 */
        val zygotePpid: Int,
        /** app-zygote 子进程自己的 maps / SELinux 域（继承自 zygote，注入痕迹会留在这里）。 */
        val zygoteMaps: String,
        val zygoteCtx: String,
    )

    private fun bind(cls: Class<*>, latch: CountDownLatch, sink: (IIsolate?) -> Unit): Boolean {
        val conn = object : android.content.ServiceConnection {
            override fun onServiceConnected(name: android.content.ComponentName?, service: android.os.IBinder?) {
                try {
                    sink(runCatching { IIsolate.Stub.asInterface(service) }.getOrNull())
                } finally {
                    latch.countDown()
                }
            }

            override fun onServiceDisconnected(name: android.content.ComponentName?) {}
        }
        val ok = runCatching {
            ctx.bindService(Intent(ctx, cls), conn, Context.BIND_AUTO_CREATE)
        }.getOrDefault(false)
        if (!ok) latch.countDown()
        return ok
    }

    /**
     * :iso / :twin 两个服务进程各跑一遍 crc，主进程拿到两份 blob 后
     * set_proc_crc() 才能让 iso_crc / twin_crc / crc_locality 真正比对
     * （ISO/TWIN crc 就是这个结构）。
     */
    fun run(): Result {
        var snap: String? = null
        var tracer = -1
        var isoCrc: String? = null
        var twinCrc: String? = null
        var zygotePpid = -1
        var zygoteMaps = ""
        var zygoteCtx = ""
        val latch = CountDownLatch(3)
        bind(IsolateService::class.java, latch) { iso ->
            if (iso != null) {
                snap = runCatching { iso.snapshot() }.getOrNull()
                tracer = runCatching { iso.tracerPid() }.getOrDefault(-1)
                isoCrc = runCatching { iso.crcBlob() }.getOrNull()
            }
        }
        bind(TwinService::class.java, latch) { twin ->
            twinCrc = runCatching { twin?.crcBlob() }.getOrNull()
        }
        // 绑定 useAppZygote 的 isolated service 会让系统拉起 <pkg>_zygote；
        // 服务进程的 PPid 就是那个 app zygote 的 pid。
        bind(ZygoteProbeService::class.java, latch) { zp ->
            zygotePpid = runCatching { zp?.ppid() ?: -1 }.getOrDefault(-1)
            zygoteMaps = runCatching { zp?.selfMaps() ?: "" }.getOrDefault("")
            zygoteCtx = runCatching { zp?.selfCtx() ?: "" }.getOrDefault("")
        }
        latch.await(12, TimeUnit.SECONDS)
        return Result(snap, tracer, isoCrc, twinCrc, zygotePpid, zygoteMaps, zygoteCtx)
    }
}
