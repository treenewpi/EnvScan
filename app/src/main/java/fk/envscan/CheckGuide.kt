package fk.envscan

import android.content.Context

/**
 * Human readable text for each check: how it is verified, and why it matched.
 *
 * The strings live in res/values/strings.xml (English, default) and the other
 * locale folders, keyed by the check id (`guide_<id>`) with a per-group
 * fallback (`guide_group_<group>`). Keeping them in resources means the app
 * follows the system language without any extra code.
 */
object CheckGuide {

    fun method(ctx: Context, item: ScanItem): String =
        stringFor(ctx, "guide_" + item.id.replace('.', '_'))
            ?: stringFor(ctx, "guide_group_" + item.group.lowercase())
            ?: ctx.getString(R.string.guide_generic)

    fun reason(ctx: Context, item: ScanItem): String {
        val first = item.detail.lineSequence().firstOrNull { it.isNotBlank() }?.trim().orEmpty()
        val evidence = first.ifEmpty { ctx.getString(R.string.guide_no_evidence) }
        val template = when (item.status) {
            Status.FAIL -> R.string.guide_reason_fail
            Status.WARN -> R.string.guide_reason_warn
            Status.PASS -> R.string.guide_reason_pass
            Status.NA -> R.string.guide_reason_na
        }
        return ctx.getString(template, evidence)
    }

    private fun stringFor(ctx: Context, name: String): String? {
        val id = ctx.resources.getIdentifier(name, "string", ctx.packageName)
        return if (id != 0) ctx.getString(id) else null
    }
}
