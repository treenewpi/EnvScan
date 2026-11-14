package fk.envscan

enum class Status { PASS, FAIL, WARN, NA }

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

    val verdict: String
        get() = when {
            items.any { it.id.startsWith("integ.libc") && it.status == Status.FAIL } ||
                items.any { it.id.contains("maps") && it.status == Status.FAIL && it.detail.contains("hook", true) } ->
                "当前程序可能已被 Hook / 修改"
            fail > 0 -> "环境异常"
            else -> "环境正常"
        }
}
