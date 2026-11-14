package fk.envscan

import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Cancel
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.ChevronRight
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Download
import androidx.compose.material.icons.rounded.HelpOutline
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.WarningAmber
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.core.view.WindowCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ScanViewModel : ViewModel() {
    private val _report = MutableStateFlow<ScanReport?>(null)
    val report: StateFlow<ScanReport?> = _report
    private val _busy = MutableStateFlow(false)
    val busy: StateFlow<Boolean> = _busy
    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error

    fun run(activity: ComponentActivity) {
        viewModelScope.launch {
            _busy.value = true
            _error.value = null
            Log.i("EnvScan", "scan start")
            try {
                val report = withContext(Dispatchers.IO) {
                    val probe = IsolateClient(activity).run()
                    ScanEngine.zygotePpid = probe.zygotePpid
                    ScanEngine.zygoteMaps = probe.zygoteMaps
                    ScanEngine.zygoteCtx = probe.zygoteCtx
                    if (probe.snapshot != null) NativeBridge.nativeSetIsolateSnap(probe.snapshot)
                    NativeBridge.nativeSetProcCrc(probe.isoCrc ?: "", probe.twinCrc ?: "")
                    val javaItems = ScanEngine.prepare(activity)
                    val nativeJson = String(NativeBridge.nativeScan(), Charsets.UTF_8)
                    val nativeItems = ScanEngine.parseNative(nativeJson, "native")
                    val hide = ScanEngine.mergeIsolate(probe.tracerPid)
                    ScanReport(nativeItems + javaItems + hide, probe.snapshot)
                }
                val path = ScanEngine.writeReport(activity, report)
                Log.i("EnvScan", "scan done items=${report.items.size} fail=${report.fail} report=$path")
                _report.value = report
            } catch (t: Throwable) {
                Log.e("EnvScan", "scan failed", t)
                _error.value = "${t.javaClass.simpleName}: ${t.message}"
                runCatching {
                    val f = java.io.File(activity.getExternalFilesDir(null) ?: activity.filesDir, "envscan-error.txt")
                    f.writeText(t.stackTraceToString())
                }
            } finally {
                _busy.value = false
            }
        }
    }
}

class MainActivity : ComponentActivity() {
    private val vm by viewModels<ScanViewModel>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        @Suppress("DEPRECATION")
        window.statusBarColor = 0xFFF5F7FA.toInt()
        @Suppress("DEPRECATION")
        window.navigationBarColor = 0xFFF5F7FA.toInt()
        WindowCompat.getInsetsController(window, window.decorView).isAppearanceLightStatusBars = true
        WindowCompat.getInsetsController(window, window.decorView).isAppearanceLightNavigationBars = true
        if (intent?.getBooleanExtra("autorun", false) == true) {
            window.decorView.postDelayed({ vm.run(this) }, 400)
        }
        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                val report by vm.report.collectAsState()
                val busy by vm.busy.collectAsState()
                val error by vm.error.collectAsState()
                EnvScanScreen(
                    report = report,
                    busy = busy,
                    error = error,
                    onScan = { vm.run(this) },
                    onExport = {
                        val r = vm.report.value
                        if (r == null) Toast.makeText(this, "先扫描一次", Toast.LENGTH_SHORT).show()
                        else Toast.makeText(this, ScanEngine.writeReport(this, r) ?: "导出失败", Toast.LENGTH_LONG).show()
                    },
                )
            }
        }
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (intent.getBooleanExtra("autorun", false)) {
            window.decorView.postDelayed({ vm.run(this) }, 400)
        }
    }
}

// ---------------------------------------------------------------- RootBeer-ish palette

private val Canvas = Color(0xFFF5F7FA)
private val Sheet = Color(0xFFFFFFFF)
private val Ink = Color(0xFF111827)
private val Sub = Color(0xFF6B7280)
private val Line = Color(0xFFE5E7EB)
private val Tint = Color(0xFFF0F3F7)
private val Red = Color(0xFFDC2626)
private val Amber = Color(0xFFD97706)
private val Green = Color(0xFF16A34A)
private val Gray = Color(0xFF9CA3AF)
private val Blue = Color(0xFF2563EB)

private val GroupOrder = listOf(
    "Root", "Injection", "Hide", "Integrity", "Identity",
    "Emulator", "Network", "Debug", "TEE", "Apps",
)

private fun statusColor(status: Status) = when (status) {
    Status.FAIL -> Red
    Status.WARN -> Amber
    Status.PASS -> Green
    Status.NA -> Gray
}

private fun statusIcon(status: Status): ImageVector = when (status) {
    Status.FAIL -> Icons.Rounded.Cancel
    Status.WARN -> Icons.Rounded.WarningAmber
    Status.PASS -> Icons.Rounded.CheckCircle
    Status.NA -> Icons.Rounded.HelpOutline
}

@Composable
fun EnvScanScreen(
    report: ScanReport?,
    busy: Boolean,
    error: String?,
    onScan: () -> Unit,
    onExport: () -> Unit,
) {
    var selected by remember { mutableStateOf<ScanItem?>(null) }
    Scaffold(containerColor = Canvas) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            TopBar(canExport = report != null, onExport = onExport)
            if (report == null) {
                EmptyState(busy = busy, error = error, onScan = onScan)
            } else {
                ReportBody(report = report, busy = busy, error = error, onScan = onScan, onItem = { selected = it })
            }
        }
    }
    selected?.let { item -> DetailDialog(item = item, onClose = { selected = null }) }
}

@Composable
private fun TopBar(canExport: Boolean, onExport: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(start = 20.dp, end = 8.dp, top = 12.dp, bottom = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text("EnvScan", color = Ink, fontSize = 20.sp, fontWeight = FontWeight.Bold, letterSpacing = (-0.3).sp)
            Text("环境检测", color = Sub, fontSize = 11.sp)
        }
        if (canExport) {
            IconButton(onClick = onExport) {
                Icon(Icons.Rounded.Download, contentDescription = "导出报告", tint = Sub)
            }
        }
    }
}

@Composable
private fun EmptyState(busy: Boolean, error: String?, onScan: () -> Unit) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp),
    ) {
        Spacer(Modifier.height(48.dp))
        Box(
            Modifier.size(64.dp).background(Blue.copy(alpha = 0.10f), CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            Icon(Icons.Rounded.Shield, contentDescription = null, tint = Blue, modifier = Modifier.size(32.dp))
        }
        Spacer(Modifier.height(22.dp))
        Text("108", color = Ink, fontSize = 64.sp, fontWeight = FontWeight.Bold, letterSpacing = (-2).sp)
        Text("项环境检查", color = Ink, fontSize = 22.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(10.dp))
        Text(
            "Root、注入、隐藏、完整性、身份、TEE 与调试环境。点开任意一条可以看到检测手法和判定原因。",
            color = Sub,
            fontSize = 13.sp,
            lineHeight = 20.sp,
        )
        Spacer(Modifier.height(28.dp))
        Button(
            onClick = onScan,
            enabled = !busy,
            shape = RoundedCornerShape(14.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Ink, contentColor = Color.White),
            modifier = Modifier.fillMaxWidth().height(52.dp),
        ) {
            if (busy) {
                CircularProgressIndicator(color = Color.White, strokeWidth = 2.dp, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(10.dp))
                Text("扫描中", fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
            } else {
                Icon(Icons.Rounded.Refresh, contentDescription = null, modifier = Modifier.size(17.dp))
                Spacer(Modifier.width(8.dp))
                Text("开始扫描", fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
            }
        }
        Spacer(Modifier.height(12.dp))
        Text("本地执行，不联网。结果只写在本机。", color = Gray, fontSize = 11.sp)
        if (error != null) {
            Spacer(Modifier.height(16.dp))
            ErrorLine(error)
        }
    }
}

@Composable
private fun ErrorLine(error: String) {
    Row(verticalAlignment = Alignment.Top) {
        Icon(Icons.Rounded.WarningAmber, contentDescription = null, tint = Amber, modifier = Modifier.size(16.dp))
        Spacer(Modifier.width(8.dp))
        Text(
            error.lineSequence().take(2).joinToString("\n"),
            color = Sub,
            fontSize = 11.5.sp,
            fontFamily = FontFamily.Monospace,
        )
    }
}

@Composable
private fun ReportBody(
    report: ScanReport,
    busy: Boolean,
    error: String?,
    onScan: () -> Unit,
    onItem: (ScanItem) -> Unit,
) {
    val risks = report.items
        .filter { it.status == Status.FAIL || it.status == Status.WARN }
        .sortedWith(compareBy({ if (it.status == Status.FAIL) 0 else 1 }, { GroupOrder.indexOf(it.group) }, { it.title }))
    val rest = report.items
        .filter { it.status != Status.FAIL && it.status != Status.WARN }
        .sortedWith(compareBy({ GroupOrder.indexOf(it.group) }, { it.title }))
    val na = report.items.count { it.status == Status.NA }

    LazyColumn(Modifier.fillMaxSize()) {
        item(key = "verdict") { Verdict(report, na) }
        item(key = "actions") {
            Row(
                Modifier.padding(horizontal = 20.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Button(
                    onClick = onScan,
                    enabled = !busy,
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Ink, contentColor = Color.White),
                    modifier = Modifier.height(46.dp),
                ) {
                    if (busy) {
                        CircularProgressIndicator(color = Color.White, strokeWidth = 2.dp, modifier = Modifier.size(15.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("扫描中", fontSize = 13.sp)
                    } else {
                        Icon(Icons.Rounded.Refresh, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(7.dp))
                        Text("重新扫描", fontSize = 13.sp, fontWeight = FontWeight.Medium)
                    }
                }
                Spacer(Modifier.width(14.dp))
                Text(
                    if (busy) "正在跑 80 个 probe" else "共 ${report.items.size} 项",
                    color = Sub,
                    fontSize = 12.sp,
                )
            }
        }
        if (error != null) {
            item(key = "error") { Box(Modifier.padding(horizontal = 20.dp, vertical = 4.dp)) { ErrorLine(error) } }
        }
        if (risks.isNotEmpty()) {
            item(key = "risk-header") { SectionLabel("风险与可疑", risks.size, Red) }
            item(key = "risk-list") { CheckList(risks, onItem) }
        }
        item(key = "rest-header") {
            SectionLabel(if (risks.isEmpty()) "全部检查" else "其余检查", rest.size, Sub)
        }
        item(key = "rest-list") { CheckList(rest, onItem) }
        item(key = "tail") { Spacer(Modifier.height(28.dp)) }
    }
}

@Composable
private fun Verdict(report: ScanReport, na: Int) {
    // 只有 FAIL 才改变总评；WARN 在计数里体现，避免“只开 ADB”被判成异常。
    val color = if (report.fail > 0) Red else Green
    val icon = if (report.fail > 0) Icons.Rounded.Cancel else Icons.Rounded.CheckCircle
    Column(
        Modifier.padding(horizontal = 20.dp, vertical = 12.dp)
            .fillMaxWidth()
            .background(Sheet, RoundedCornerShape(20.dp))
            .padding(18.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(46.dp).background(color.copy(alpha = 0.10f), CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(26.dp))
            }
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    report.verdict,
                    color = Ink,
                    fontSize = 28.sp,
                    lineHeight = 32.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = (-0.5).sp,
                )
                Text(
                    "${report.items.size} 项检查，${report.fail + report.warn} 项待处理",
                    color = Sub,
                    fontSize = 12.sp,
                    modifier = Modifier.padding(top = 2.dp),
                )
            }
        }
        Spacer(Modifier.height(16.dp))
        RatioBar(report.fail, report.warn, report.pass, na)
        Spacer(Modifier.height(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(14.dp)) {
            Text("${report.fail} 风险", color = Red, fontSize = 11.sp)
            Text("${report.warn} 可疑", color = Amber, fontSize = 11.sp)
            Text("${report.pass} 通过", color = Green, fontSize = 11.sp)
            if (na > 0) Text("$na 待定", color = Gray, fontSize = 11.sp)
        }
    }
}

@Composable
private fun RatioBar(fail: Int, warn: Int, pass: Int, na: Int) {
    val total = (fail + warn + pass + na).coerceAtLeast(1)
    Row(Modifier.fillMaxWidth().height(7.dp).clip(RoundedCornerShape(4.dp))) {
        Segment(fail, total, Red)
        Segment(warn, total, Amber)
        Segment(pass, total, Green.copy(alpha = 0.65f))
        Segment(na, total, Line)
    }
}

@Composable
private fun androidx.compose.foundation.layout.RowScope.Segment(count: Int, total: Int, color: Color) {
    if (count <= 0) return
    Box(Modifier.weight(count.toFloat() / total).fillMaxSize().background(color))
}

@Composable
private fun SectionLabel(title: String, count: Int, color: Color) {
    Row(
        Modifier.fillMaxWidth().padding(start = 22.dp, end = 22.dp, top = 20.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(title, color = Ink, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.width(8.dp))
        Text("$count", color = color, fontSize = 12.sp)
    }
}

@Composable
private fun CheckList(items: List<ScanItem>, onItem: (ScanItem) -> Unit) {
    Column(
        Modifier.padding(horizontal = 20.dp)
            .fillMaxWidth()
            .background(Sheet, RoundedCornerShape(16.dp)),
    ) {
        items.forEachIndexed { index, item ->
            CheckRow(item, onClick = { onItem(item) })
            if (index != items.lastIndex) {
                HorizontalDivider(
                    color = Line,
                    thickness = 0.6.dp,
                    modifier = Modifier.padding(start = 52.dp),
                )
            }
        }
    }
}

@Composable
private fun CheckRow(item: ScanItem, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(start = 16.dp, end = 12.dp, top = 12.dp, bottom = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            statusIcon(item.status),
            contentDescription = null,
            tint = statusColor(item.status),
            modifier = Modifier.size(21.dp),
        )
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Text(
                item.title,
                color = Ink,
                fontSize = 14.5.sp,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                CheckGuide.method(item),
                color = Sub,
                fontSize = 11.sp,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.padding(top = 3.dp),
            )
        }
        Spacer(Modifier.width(8.dp))
        Icon(Icons.Rounded.ChevronRight, contentDescription = null, tint = Color(0xFFC4CAD3), modifier = Modifier.size(17.dp))
    }
}

@Composable
private fun DetailDialog(item: ScanItem, onClose: () -> Unit) {
    val clipboard = LocalClipboardManager.current
    val ctx = LocalContext.current
    Dialog(onDismissRequest = onClose) {
        Surface(shape = RoundedCornerShape(20.dp), color = Sheet) {
            Column(
                Modifier.fillMaxWidth().heightIn(max = 640.dp).padding(22.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        statusIcon(item.status),
                        contentDescription = null,
                        tint = statusColor(item.status),
                        modifier = Modifier.size(22.dp),
                    )
                    Spacer(Modifier.width(10.dp))
                    Text(
                        if (item.status == Status.FAIL) "风险" else if (item.status == Status.WARN) "可疑" else if (item.status == Status.NA) "无法判定" else "通过",
                        color = statusColor(item.status),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Spacer(Modifier.weight(1f))
                    IconButton(onClick = onClose, modifier = Modifier.size(30.dp)) {
                        Icon(Icons.Rounded.Close, contentDescription = "关闭", tint = Sub, modifier = Modifier.size(18.dp))
                    }
                }
                Text(
                    item.title,
                    color = Ink,
                    fontSize = 20.sp,
                    lineHeight = 26.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(top = 2.dp),
                )
                Text(
                    "${item.group}  /  ${item.id}",
                    color = Gray,
                    fontSize = 10.5.sp,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier.padding(top = 4.dp),
                )
                Spacer(Modifier.height(16.dp))
                Label("检测手法")
                Text(CheckGuide.method(item), color = Ink, fontSize = 13.sp, lineHeight = 20.sp)
                Spacer(Modifier.height(14.dp))
                Label("原因")
                Text(CheckGuide.reason(item), color = Ink, fontSize = 13.sp, lineHeight = 20.sp)
                Spacer(Modifier.height(14.dp))
                Label("原始证据")
                Box(
                    Modifier.fillMaxWidth().heightIn(max = 180.dp)
                        .background(Tint, RoundedCornerShape(10.dp))
                        .verticalScroll(rememberScrollState())
                        .padding(12.dp),
                ) {
                    Text(
                        item.detail.ifBlank { "(无详情)" },
                        color = Color(0xFF374151),
                        fontSize = 11.5.sp,
                        lineHeight = 17.sp,
                        fontFamily = FontFamily.Monospace,
                    )
                }
                Spacer(Modifier.height(16.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    TextButton(
                        onClick = {
                            clipboard.setText(AnnotatedString("${item.title}\n${item.id}\n\n检测手法：\n${CheckGuide.method(item)}\n\n原因：\n${CheckGuide.reason(item)}\n\n证据：\n${item.detail}"))
                            Toast.makeText(ctx, "已复制", Toast.LENGTH_SHORT).show()
                        },
                    ) {
                        Icon(Icons.Rounded.ContentCopy, contentDescription = null, tint = Sub, modifier = Modifier.size(15.dp))
                        Spacer(Modifier.width(7.dp))
                        Text("复制", color = Sub, fontSize = 12.sp)
                    }
                    Spacer(Modifier.weight(1f))
                    Button(
                        onClick = onClose,
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Ink, contentColor = Color.White),
                        modifier = Modifier.height(40.dp),
                    ) { Text("关闭", fontSize = 13.sp) }
                }
            }
        }
    }
}

@Composable
private fun Label(text: String) {
    Text(text, color = Sub, fontSize = 11.sp, fontWeight = FontWeight.Medium, modifier = Modifier.padding(bottom = 5.dp))
}
