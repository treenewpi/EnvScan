package fk.envscan

enum class Status { PASS, FAIL, WARN, NA }

/** Overall verdict; the UI maps it to a localized string. */
enum class Verdict { HOOKED, ABNORMAL, NORMAL }

data class ScanItem(
    val id: String,
    val group: String,
    val title: String,
    val status: Status,
    val detail: String,
    val source: String = "",
)

data class ScanReport(
    val items: List<ScanItem>,
    val isolateJson: String? = null,
) {
    val fail: Int get() = items.count { it.status == Status.FAIL }
    val warn: Int get() = items.count { it.status == Status.WARN }
    val pass: Int get() = items.count { it.status == Status.PASS }

    val verdict: Verdict
        get() = when {
            items.any { it.id.startsWith("integ.libc") && it.status == Status.FAIL } ||
                items.any { it.id.contains("maps") && it.status == Status.FAIL && it.detail.contains("hook", true) } ->
                Verdict.HOOKED
            fail > 0 -> Verdict.ABNORMAL
            else -> Verdict.NORMAL
        }
}
