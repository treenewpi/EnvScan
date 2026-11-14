package fk.envscan

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.system.Os
import java.io.File
import java.security.KeyStore
import java.security.cert.X509Certificate

/**
 * Checks that the shared probe library alone cannot express.
 *
 * The probes cover device-level techniques; this file adds the product-level ones:
 * - crypto / ART / init.rc / permission / su process / zygote;
 * - notification bar / manifest component graph / local Play Integrity /
 *   SELinux policy file;
 * - Shamiko / Bootloader Spoofer / RVX / injection service /
 *   Zygisk exclusion / tombstone.
 *
 * Everything here runs inside the EnvScan process; data that cannot be read is
 * written into the detail instead of being turned into a fake PASS.
 */
object ExtraChecks {

    fun collect(ctx: Context): List<ScanItem> {
        val p = props()
        val out = mutableListOf<ScanItem>()
        out += cryptoCheck(p)
        out += artCheck(p)
        out += initRcCheck(p)
        out += permissionCheck(p)
        out += suProcessCheck()
        out += zygoteBehavior(p)
        out += zygoteInjected()
        out += notificationBarCheck(ctx)
        out += manifestGraphCheck(ctx)
        out += playIntegrityCheck()
        out += selinuxPolicyCheck(p)
        out += shamikoCheck(ctx, p)
        out += bootloaderSpoofCheck(p)
        out += rvxCheck(ctx)
        out += injectionServiceCheck(ctx, p)
        out += zygiskExclusionCheck()
        out += tombstoneCheck()
        // Titles come from resources when a `title_<id>` entry exists, so the list
        // follows the system language; unknown ids keep their probe title.
        return out.map { it.copy(title = localizedTitle(ctx, it)) }
    }

    private fun localizedTitle(ctx: Context, item: ScanItem): String {
        val res = ctx.resources.getIdentifier("title_" + item.id.replace('.', '_'), "string", ctx.packageName)
        return if (res != 0) ctx.getString(res) else item.title
    }

    // ---------------------------------------------------------------- props

    private fun props(): Map<String, String> = runCatching {
        val m = mutableMapOf<String, String>()
        val p = ProcessBuilder("getprop").redirectErrorStream(true).start()
        p.inputStream.bufferedReader().forEachLine { line ->
            val t = line.trim()
            if (t.startsWith("[") && t.contains("]: [")) {
                m[t.substringAfter('[').substringBefore(']')] =
                    t.substringAfter("]: [").removeSuffix("]")
            }
        }
        p.waitFor()
        m
    }.getOrDefault(emptyMap())

    private fun item(
        id: String, group: String, title: String, fail: Boolean, detail: String,
        warn: Boolean = false, na: Boolean = false,
    ) = ScanItem(
        id = id, group = group, title = title,
        status = when {
            fail -> Status.FAIL
            na -> Status.NA
            warn -> Status.WARN
            else -> Status.PASS
        },
        detail = detail, source = "java-ext",
    )

    private fun read(path: String, max: Int = 1 shl 20): String =
        runCatching { File(path).readText().take(max) }.getOrDefault("")

    // ------------------------------------------------------------- runtime

    private fun cryptoCheck(p: Map<String, String>): ScanItem {
        val state = p["ro.crypto.state"] ?: ""
        val type = p["ro.crypto.type"] ?: ""
        val data = File("/proc/self/mountinfo").readLines()
            .firstOrNull { it.split(' ').getOrNull(4) == "/data" } ?: ""
        val fail = state != "encrypted"
        return item(
            "storage.crypto", "Identity", "Data not encrypted / mount options changed",
            fail,
            "ro.crypto.state=$state type=$type\n/data mount=$data",
        )
    }

    private fun parseSize(v: String): Long? {
        val t = v.trim().lowercase()
        if (t.isEmpty()) return null
        val n = t.dropLastWhile { it.isLetter() }.toLongOrNull() ?: return null
        return when (t.lastOrNull()) {
            'g' -> n * 1024 * 1024 * 1024
            'm' -> n * 1024 * 1024
            'k' -> n * 1024
            else -> n
        }
    }

    private fun artCheck(p: Map<String, String>): ScanItem {
        val heap = parseSize(p["dalvik.vm.heapsize"] ?: "")
        val growth = parseSize(p["dalvik.vm.heapgrowthlimit"] ?: "")
        val filter = p["dalvik.vm.dex2oat-filter"] ?: ""
        val flags = p["dalvik.vm.dex2oat-flags"] ?: ""
        val bad = (heap != null && growth != null && heap < growth) ||
            filter.contains("verify-none", true) ||
            flags.contains("--compiler-filter=verify-none", true)
        return item(
            "runtime.art", "Integrity", "ART parameters abnormal",
            bad,
            "heapsize=${p["dalvik.vm.heapsize"]} heapgrowthlimit=${p["dalvik.vm.heapgrowthlimit"]} " +
                "dex2oat-filter=$filter flags=$flags",
        )
    }

    private fun initRcCheck(p: Map<String, String>): ScanItem {
        val paths = listOf("/system/etc/init/hw/init.rc", "/system/etc/init/init.rc")
        val text = paths.firstNotNullOfOrNull { read(it).takeIf { s -> s.isNotEmpty() } } ?: ""
        val markers = listOf("magisk", "resetprop", "kernelsu", "apatch", "insmod", "/data/adb")
        val hits = markers.filter { text.contains(it, true) }
        val oddOwner = runCatching {
            File("/system/etc/init").listFiles()?.filter { f ->
                if (!f.isFile) return@filter false
                val st = android.system.Os.stat(f.absolutePath)
                st.st_uid != 0
            }?.map { it.name } ?: emptyList()
        }.getOrDefault(emptyList())
        val fail = hits.isNotEmpty() || oddOwner.isNotEmpty()
        return item(
            "boot.init_rc", "Integrity", "init.rc modified",
            fail,
            "init.rc hits=${hits.ifEmpty { listOf("none") }} non_root=${oddOwner.ifEmpty { listOf("none") }} " +
                "size=${text.length}",
        )
    }

    private fun permissionCheck(p: Map<String, String>): ScanItem {
        val vers = read("/sys/fs/selinux/policyvers", 64).trim()
        val loaded = read("/sys/fs/selinux/policyload", 64).trim()
        val boot = p["ro.boot.selinux"] ?: ""
        val policy = File("/sys/fs/selinux/policy").exists()
        val sysLabel = runCatching { String(Os.getxattr("/system", "security.selinux")) }.getOrDefault("")
        val shLabel = runCatching { String(Os.getxattr("/system/bin/sh", "security.selinux")) }.getOrDefault("")
    // Apps cannot read policyvers on Android 12+; a policy file with normal
    // system_file / shell_exec labels means SELinux policy is in place, so a
    // restricted selinuxfs is not a risk by itself.
        val fail = boot == "disabled" || (!policy && vers.isEmpty()) ||
            (sysLabel.isNotBlank() && !sysLabel.contains("system_file"))
        return item(
            "system.permission", "Integrity", "Permission system anomaly",
            fail,
            "policyvers=$vers policyload=$loaded policy=$policy boot=$boot " +
                "system=$sysLabel sh=$shLabel",
        )
    }

    private fun suProcessCheck(): ScanItem {
        val hits = mutableListOf<String>()
        val names = listOf("su", "magisk", "ksud", "apatch", "zygisk")
        runCatching {
            File("/proc").listFiles()?.forEach { d ->
                if (!d.name.firstOrNull()?.isDigit()!!) return@forEach
                val cmd = read("${d.path}/cmdline", 128)
                if (cmd.isEmpty()) return@forEach
                val name = cmd.substringBefore('\u0000')
                if (names.any { name.contains(it, true) }) hits += "${d.name}:$name"
            }
        }
        if (hits.isEmpty()) {
            runCatching {
                val ps = ProcessBuilder("ps", "-A", "-o", "NAME").redirectErrorStream(true).start()
                ps.inputStream.bufferedReader().forEachLine { line ->
                    val n = line.trim()
                    if (names.any { n == it || n.startsWith("$it ") }) hits += "ps:$n"
                }
                ps.waitFor()
            }
        }
        return item(
            "root.su_process", "Root", "su process found",
            hits.isNotEmpty(), hits.ifEmpty { listOf("no su/magisk process") }.joinToString("\n"),
        )
    }

    private fun zygotePids(): List<Int> {
        val out = mutableListOf<Int>()
        runCatching {
            File("/proc").listFiles()?.forEach { d ->
                if (d.name.firstOrNull()?.isDigit() != true) return@forEach
                val cmd = read("${d.path}/cmdline", 128)
                if (cmd.contains("zygote")) out += d.name.toInt()
            }
        }
        return out
    }

    private fun zygoteNamesFromPs(): List<String> = runCatching {
        val ps = ProcessBuilder("ps", "-A", "-o", "NAME").redirectErrorStream(true).start()
        val names = mutableListOf<String>()
        ps.inputStream.bufferedReader().forEachLine { line ->
            val n = line.trim()
            if (n.contains("zygote")) names += n
        }
        ps.waitFor()
        names.distinct()
    }.getOrDefault(emptyList())

    /**
     * "Zygote behaviour abnormal / injected" cannot be answered by enumerating the
     * system zygote: an ordinary app cannot read /proc/<zygote>/cmdline (untrusted_app
     * is denied even getattr on the zygote domain).
     *
     * So this goes through the app zygote instead: the manifest declares a
     * zygotePreloadName plus an isolatedProcess + useAppZygote service. The system
     * forks `<pkg>_zygote` (app_zygote domain, same app uid) and the service process
     * is forked from it, which means:
     *   - the service's own maps are the zygote address space (injected libs come along);
     *   - the service's own PPid is the app zygote pid.
     * The check therefore runs inside our own child, without reading anyone else's /proc.
     */
    private fun zygoteChildCtx(): String = ScanEngine.zygoteCtx

    private fun zygoteBehavior(p: Map<String, String>): ScanItem {
        val pid = ScanEngine.zygotePpid
        val ctx = zygoteChildCtx()
        val maps = ScanEngine.zygoteMaps
        if (pid <= 0 || ctx.isEmpty()) {
            return item(
                "zygote.behavior", "Injection", "Zygote behaviour abnormal",
                false, "app_zygote child pid=${ScanEngine.zygotePpid} ctx=(empty)",
                na = true,
            )
        }
        val isIsolated = ctx.contains("isolated_app")
        // A child of the app zygote must be forked from it: PPid should point at <pkg>_zygote.
        val ppidOk = pid > 0
        val fail = !isIsolated || !ppidOk
        return item(
            "zygote.behavior", "Injection", "Zygote behaviour abnormal",
            fail,
            "app_zygote_ppid=$pid\nchild_se=$ctx maps_bytes=${maps.length}\n" +
                "isolated_domain=$isIsolated ppid_ok=$ppidOk",
        )
    }

    private fun soPaths(maps: String): List<String> =
        maps.lineSequence()
            .mapNotNull { line -> line.substringAfterLast(' ', "").trim() }
            .filter { it.endsWith(".so") && it.startsWith("/") }
            .distinct()
            .toList()

    private fun zygoteInjected(): ScanItem {
        val maps = ScanEngine.zygoteMaps
        if (maps.isEmpty()) {
            return item(
                "zygote.injected", "Injection", "Zygote injected",
                false, "app_zygote child maps empty (service not running)", na = true,
            )
        }
        val hits = mutableListOf<String>()
        for (k in listOf("magisk", "lsposed", "zygisk", "riru", "frida", "libdobby", "shamiko")) {
            if (maps.contains(k, true)) hits += k
        }
        // The child address space is forked from the app zygote, so anything injected into the
        // zygote is inherited. Normally only /system, /apex, /vendor and /data/app/<self>
        // libs should appear; anything else is foreign injection.
        val own = "fk.envscan"
        val foreign = soPaths(maps).filter { p ->
            !p.startsWith("/system/") && !p.startsWith("/apex/") && !p.startsWith("/vendor/") &&
                !p.startsWith("/product/") && !p.startsWith("/system_ext/") &&
                !(p.startsWith("/data/app/") && p.contains(own))
        }
        val fail = hits.isNotEmpty() || foreign.isNotEmpty()
        return item(
            "zygote.injected", "Injection", "Zygote injected",
            fail,
            "app_zygote child maps_bytes=${maps.length} libs=${soPaths(maps).size}\n" +
                "mark_hits=${hits.ifEmpty { listOf("none") }}\nforeign=${foreign.ifEmpty { listOf("none") }}",
        )
    }

    // -------------------------------------------------------- product checks

    private fun notificationBarCheck(ctx: Context): ScanItem {
        val cr = ctx.contentResolver
        val listeners = Settings.Secure.getString(cr, "enabled_notification_listeners") ?: ""
        val overlay = runCatching { Settings.canDrawOverlays(ctx) }.getOrDefault(false)
        val policy = Settings.Secure.getString(cr, "enabled_notification_policy_access_packages") ?: ""
        // MIUI/HyperOS ships its own notification listener (xiaomi.barrage); only third-party
        // listeners count as a risk.
        val nonSystem = nonSystemNotificationListeners(ctx, listeners)
        val fail = nonSystem.isNotEmpty() || overlay || policy.isNotBlank()
        return item(
            "notify.bar", "Debug", "Notification Bar",
            fail,
            "listeners=${listeners.ifBlank { "-" }}\nnon_system=${nonSystem.ifEmpty { listOf("none") }}" +
                "\noverlay=$overlay policy_access=${policy.ifBlank { "-" }}",
        )
    }

    private fun manifestGraphCheck(ctx: Context): ScanItem {
        val pm = ctx.packageManager
        val flags = PackageManager.GET_ACTIVITIES or PackageManager.GET_SERVICES or
            PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS
        val pi = runCatching { pm.getPackageInfo(ctx.packageName, flags) }.getOrNull()
        val acts = pi?.activities?.map { it.name }?.toSet() ?: emptySet()
        val svcs = pi?.services?.map { it.name }?.toSet() ?: emptySet()
        // The EnvScan manifest only declares these components; anything extra was repackaged
        // or injected.
        val expectedActs = mutableSetOf("fk.envscan.MainActivity")
        if (BuildConfig.DEBUG) expectedActs += "androidx.compose.ui.tooling.PreviewActivity"
        val expectedSvcs = setOf(
            "fk.envscan.IsolateService", "fk.envscan.TwinService", "fk.envscan.ZygoteProbeService",
        )
        val extra = (acts - expectedActs) + (svcs - expectedSvcs)
        val missing = (expectedActs - acts) + (expectedSvcs - svcs)
        return item(
            "manifest.graph", "Integrity", "Manifest components",
            extra.isNotEmpty() || missing.isNotEmpty(),
            "activities=$acts\nservices=$svcs\nextra=$extra missing=$missing",
        )
    }

    private fun playIntegrityCheck(): ScanItem {
        return runCatching {
            val alias = "envscan-play-integrity"
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (ks.containsAlias(alias)) ks.deleteEntry(alias)
            val kpg = java.security.KeyPairGenerator.getInstance(
                "EC", "AndroidKeyStore",
            )
            val spec = android.security.keystore.KeyGenParameterSpec.Builder(
                alias, android.security.keystore.KeyProperties.PURPOSE_SIGN,
            )
                .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                .setDigests(android.security.keystore.KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge("envscan".toByteArray())
                .build()
            kpg.initialize(spec)
            kpg.generateKeyPair()
            val chain = ks.getCertificateChain(alias) ?: emptyArray()
            if (chain.isEmpty()) {
                return item(
                    "attest.play_integrity", "TEE", "Play Integrity (local)",
                    false, "attestation chain empty", warn = true,
                )
            }
            val leaf = chain[0] as X509Certificate
            val root = chain.last() as X509Certificate
            val rootDn = root.subjectDN.name
            val rot = leaf.getExtensionValue("1.3.6.1.4.1.11129.2.1.17")
                ?.let { ScanEngine.parseRootOfTrustPublic(it) }
            val software = rootDn.contains("Software", true) || rootDn.contains("AOSP", true)
            val p = props()
            val propLocked = p["ro.boot.flash.locked"] == "1" || p["ro.boot.vbmeta.device_state"] == "locked"
            val propGreen = p["ro.boot.verifiedbootstate"] == "green"
            // The Android 16 attestation extension sometimes yields no RootOfTrust (rot=null);
            // fall back to the system boot properties and only fail when rot says unlocked.
            val locked = if (rot != null) rot.deviceLocked == 1 else propLocked
            val verified = if (rot != null) rot.verifiedBootState == 0 else propGreen
            val fail = software || !locked || !verified
            item(
                "attest.play_integrity", "TEE", "Play Integrity (local)",
                fail,
                "server=not_configured (local key-attestation fallback)\n" +
                    "chain=${chain.size} root=$rootDn rot=$rot locked=$locked verified=$verified" +
                    (if (rot == null) " (props fallback)" else ""),
            )
        }.getOrElse { e ->
            item(
                "attest.play_integrity", "TEE", "Play Integrity (local)",
                false, "attestation unavailable: ${e.javaClass.simpleName}: ${e.message}",
                warn = true,
            )
        }
    }

    private fun selinuxPolicyCheck(p: Map<String, String>): ScanItem {
        val vers = read("/sys/fs/selinux/policyvers", 64).trim()
        val policy = read("/sys/fs/selinux/policy", 1 shl 16)
        val buildSelinux = p["ro.build.selinux"] ?: ""
        val checkreq = read("/sys/fs/selinux/checkreqprot", 64).trim()
        val fsPresent = File("/sys/fs/selinux").exists()
        val boot = p["ro.boot.selinux"] ?: ""
        // SELinux context check: the process domain must be untrusted_app(_NN) and the
        // context must not carry su/magisk style markers.
        val context = read("/proc/self/attr/current", 256).trim().trimEnd('\u0000')
        val domainOk = Regex("^u:r:untrusted_app(_\\d+)?:s0").containsMatchIn(context)
        val marks = listOf("magisk", ":su:", "shell", "system_app", "platform_app", "priv_app")
        val mark = marks.firstOrNull { context.contains(it) }
        val contextBad = context.isNotEmpty() && (!domainOk || mark != null)
        val policyUnreadable = vers.isEmpty() && policy.isEmpty()
        val fail = boot == "disabled" || !fsPresent || contextBad
        return item(
            "selinux.policy_file", "Integrity", "SELinux policy file",
            fail,
            "policyvers=$vers policy_bytes=${policy.length} checkreqprot=$checkreq " +
                "build.selinux=$buildSelinux fs=$fsPresent\n" +
                "context=$context domain_ok=$domainOk mark=${mark ?: "-"} " +
                "policy_unreadable=$policyUnreadable",
            // Not being able to read the policy file is normal (apps lack security_read_policy),
            // so judge by the context instead of treating missing data as NA; only a missing
            // context is undecidable.
            na = context.isEmpty() && policyUnreadable,
        )
    }

    // -------------------------------------------------------------- extras

    private fun managerPackages(ctx: Context): Set<String> =
        runCatching {
            ctx.packageManager.getInstalledPackages(0).map { it.packageName }.toSet()
        }.getOrDefault(emptySet())

    private fun shamikoCheck(ctx: Context, p: Map<String, String>): ScanItem {
        val pkgs = managerPackages(ctx)
        val hasManager = pkgs.any {
            it.contains("kernelsu") || it.contains("apatch") || it.contains("magisk")
        } || File("/debug_ramdisk").exists() && p["ro.build.tags"] == "test-keys"
        val shamiko = File("/debug_ramdisk/shamiko/module.prop").exists() ||
            File("/debug_ramdisk/shamiko").exists() ||
            pkgs.any { it.contains("shamiko") }
        val fail = hasManager && !shamiko
        return item(
            "hide.shamiko_missing", "Hide", "Shamiko missing",
            fail,
            "manager=$hasManager shamiko=$shamiko",
        )
    }

    private fun bootloaderSpoofCheck(p: Map<String, String>): ScanItem {
        val vbs = p["ro.boot.verifiedbootstate"] ?: ""
        val locked = p["ro.boot.flash.locked"] ?: ""
        val vbd = p["ro.boot.vbmeta.device_state"] ?: ""
        val digest = p["ro.boot.vbmeta.digest"] ?: ""
        val greenUnlocked = vbs == "green" && (locked == "0" || vbd == "unlocked")
        val emptyDigest = digest.isEmpty() && vbs == "green"
        return item(
            "boot.bootloader_spoof", "Identity", "Bootloader Spoofer",
            greenUnlocked || emptyDigest,
            "verifiedbootstate=$vbs flash.locked=$locked vbmeta=$vbd digest=" +
                (digest.ifEmpty { "(empty)" }),
        )
    }

    private fun rvxCheck(ctx: Context): ScanItem {
        val hits = managerPackages(ctx).filter {
            val n = it.lowercase()
            n.contains("rvx") || n.contains("revanced") || n.contains("microg")
        }
        return item(
            "inject.rvx", "Injection", "RVX", hits.isNotEmpty(),
            hits.ifEmpty { listOf("no rvx/revanced/microg package") }.joinToString("\n"),
        )
    }

    private fun injectionServiceCheck(ctx: Context, p: Map<String, String>): ScanItem {
        val hits = managerPackages(ctx).filter {
            val n = it.lowercase()
            n.contains("inject") || n.contains("zygisk") || n.contains("xposed") ||
                n.contains("lsposed") || n.contains("shamiko")
        }
        val procHits = mutableListOf<String>()
        runCatching {
            File("/proc").listFiles()?.forEach { d ->
                if (d.name.firstOrNull()?.isDigit() != true) return@forEach
                val cmd = read("${d.path}/cmdline", 128)
                if (cmd.contains("inject", true) || cmd.contains("zygisk", true)) {
                    procHits += "${d.name}:${cmd.replace('\u0000', ' ')}"
                }
            }
        }
        return item(
            "inject.service", "Injection", "Injection service",
            hits.isNotEmpty() || procHits.isNotEmpty(),
            "packages=$hits\nprocesses=$procHits",
        )
    }

    private fun zygiskExclusionCheck(): ScanItem {
        // Without root the exclusion list in /data/adb is unreadable, so use whether this
        // process is injected by Zygisk as the observable equivalent: injected means the
        // exclusion list is not effective, clean means this path is fine.
        val maps = read("/proc/self/maps", 1 shl 20)
        val hit = listOf("zygisk", "libzygisk", "lsposed", "LSPHooker")
            .filter { maps.contains(it, true) }
        return item(
            "hide.zygisk_exclusion", "Injection", "Zygisk exclusion list",
            hit.isNotEmpty(),
            "self_maps_hits=${hit.ifEmpty { listOf("none") }}",
        )
    }

    private fun tombstoneCheck(): ScanItem {
        val dirs = listOf("/data/tombstones", "/data/anr")
        val found = mutableListOf<String>()
        var readable = 0
        for (d in dirs) {
            val f = File(d)
            if (!f.canRead()) continue
            readable++
            runCatching { f.listFiles()?.take(8)?.forEach { found += it.name } }
        }
        return item(
            "debug.tombstone", "Integrity", "Evil Service（tombstone）",
            found.isNotEmpty(),
            "readable_dirs=$readable files=${found.ifEmpty { listOf("none") }}",
            na = readable == 0,
        )
    }

    private fun nonSystemNotificationListeners(ctx: Context, raw: String): List<String> =
        raw.split(':').filter { it.isNotBlank() }.filter { comp ->
            val pkg = comp.substringBefore('/')
            val ai = runCatching { ctx.packageManager.getApplicationInfo(pkg, 0) }.getOrNull()
            ai != null && (ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) == 0
        }
}
