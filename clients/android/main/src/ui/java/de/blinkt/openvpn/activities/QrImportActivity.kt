package de.blinkt.openvpn.activities

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import de.blinkt.openvpn.LaunchVPN
import de.blinkt.openvpn.R
import de.blinkt.openvpn.core.ConfigParser
import de.blinkt.openvpn.core.OpenVPNService
import de.blinkt.openvpn.core.ProfileManager
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.StringReader
import java.util.concurrent.TimeUnit
import java.util.regex.Pattern

/**
 * P1：App 内扫码导入（ANDROID-QR-AUTH-DESIGN §二）。
 * 扫门户二维码（内容 = 一次性下载链接 + name + u）→ 域名白名单硬校验（防二维码投毒）
 * → HTTPS 下载（NSC 信任 opensec.crt，OkHttp 走平台信任）→ 确定性命名导入（同名替换，根治 #39 重复条目）
 * → 凭据预填（username=会话归属键，password 占位——服务端 webauth 不验密码，与 Windows auth-user.txt 同语义）
 * → 自动连接（决议 Q2）。配置持久化，下次进入 App 直接续连。
 */
class QrImportActivity : BaseActivity() {

    private lateinit var status: TextView
    private lateinit var progress: ProgressBar
    private lateinit var retry: Button
    private var lastUrl: String? = null
    private var lastDeepLink: Uri? = null

    private val scanLauncher = registerForActivityResult(ScanContract()) { result ->
        if (result.contents == null) {
            // 用户取消扫码：无已导入配置时留在本页可重扫，否则直接回列表
            if (!hasAnyProfile()) finish()
        } else {
            handleScannedUrl(result.contents)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_qr_import)
        status = findViewById(R.id.qr_status)
        progress = findViewById(R.id.qr_progress)
        retry = findViewById(R.id.qr_rescan)
        retry.setOnClickListener {
            // P5：深链失败重试=重走深链；扫码路径重试=重开扫码
            val d = lastDeepLink
            if (d != null) handleModsafeDeepLink(d) else launchScanner()
        }
        // P5：浏览器完成 IM SSO 后 modsafe://setup 回跳 → 直接进下载管线；否则常规扫码
        val data = intent?.data
        if (data != null && data.scheme == "modsafe") {
            lastDeepLink = data
            handleModsafeDeepLink(data)
        } else {
            launchScanner()
        }
    }

    private fun launchScanner() {
        status.text = getString(R.string.qr_scan_prompt)
        progress.visibility = View.GONE
        retry.visibility = View.GONE
        val opts = ScanOptions().apply {
            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            setPrompt(getString(R.string.qr_scan_prompt))
            setBeepEnabled(false)
            // 2026-10-07 用户反馈：扫码应随设备自适应竖屏/横屏（zxing 默认锁横屏）
            setOrientationLocked(false)
        }
        scanLauncher.launch(opts)
    }

    private fun handleScannedUrl(raw: String) {
        lastUrl = raw
        val uri = Uri.parse(raw)
        val host = uri.host ?: ""
        val path = uri.path ?: ""
        val name = uri.getQueryParameter("name") ?: ""
        // ADR-3：仅允许 modsafe 下载域，路径必须命中一次性下载端点，name 白名单与 launcher nameRe 同口径
        if (uri.scheme != "https" || host !in allowedHosts(this) ||
            !path.startsWith("/api/v1/client-config/") || !NAME_RE.matcher(name).matches()
        ) {
            fail(getString(R.string.qr_bad_source))
            return
        }
        startDownload(raw, name, uri.getQueryParameter("u") ?: "", uri.getQueryParameter("g") ?: "")
    }

    /**
     * P5（2026-10-07）：门户深链导入——浏览器完成企微/钉钉/飞书 SSO 后，modsafe://setup?token=&base=&name=&u= 回跳。
     * base 硬校验（https + 白名单 host，拒绝任意站点构造链接投毒配置；白名单含两个内网 IP 属产品既有入口），
     * 下载 URL = base + /api/v1/client-config/<token>，与 Windows launcher v3.3.23 的 base 跟随同语义；
     * 白名单域经 network_security_config pin 到 opensec.crt。
     */
    private fun handleModsafeDeepLink(uri: Uri) {
        lastUrl = uri.toString()
        val token = uri.getQueryParameter("token") ?: ""
        val base = uri.getQueryParameter("base") ?: ""
        val name = uri.getQueryParameter("name") ?: ""
        val b = Uri.parse(base)
        if (b.scheme != "https" || (b.host ?: "") !in allowedHosts(this) ||
            !TOKEN_RE.matcher(token).matches() || !NAME_RE.matcher(name).matches()
        ) {
            fail(getString(R.string.qr_bad_source))
            return
        }
        startDownload(base + "/api/v1/client-config/" + token, name, uri.getQueryParameter("u") ?: "",
            uri.getQueryParameter("g") ?: "")
    }

    /** B 方案（网页一键连接免验证）：门户随下载链接签发的一次性 ticket 落盘 App 私有目录，
     *  OpenVPNService 打开验证页时附加 &grant= 并即删。白名单=hex；空/非法不落盘（行为同从前）。 */
    private fun stageConnectGrant(grant: String) {
        if (!GRANT_RE.matcher(grant).matches()) {
            de.blinkt.openvpn.core.VpnStatus.logInfo("模方安全：深链未携带有效连接票据（g 参数缺失或格式异常）")
            return
        }
        try {
            filesDir.resolve("modsafe-grant.txt").writeText(grant)
            de.blinkt.openvpn.core.VpnStatus.logInfo("模方安全：连接票据已暂存（连接时自动静默认证）")
        } catch (_: Exception) {
            /* 落盘失败仅退化为需验证，不阻断导入 */
        }
    }

    private fun startDownload(url: String, name: String, user: String, grant: String) {
        stageConnectGrant(grant)
        progress.visibility = View.VISIBLE
        retry.visibility = View.GONE
        status.text = getString(R.string.qr_downloading)
        Thread {
            try {
                val body = downloadConfig(url)
                val profile = parseProfile(body, name, user)
                runOnUiThread { importAndConnect(profile) }
            } catch (e: Exception) {
                runOnUiThread { fail(getString(R.string.qr_download_fail, e.localizedMessage ?: "")) }
            }
        }.start()
    }

    private fun downloadConfig(url: String): String {
        val client = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .build()
        client.newCall(Request.Builder().url(url).build()).execute().use { resp ->
            if (!resp.isSuccessful) throw IllegalStateException("HTTP ${resp.code}")
            val body = resp.body?.string() ?: throw IllegalStateException("empty body")
            // 与 launcher 同口径的内容校验：非 .ovpn 一律拒绝
            if (!(body.startsWith("#") || body.startsWith("client")) || !body.contains("<ca>")) {
                throw IllegalStateException("not an ovpn profile")
            }
            return body
        }
    }

    private fun parseProfile(body: String, name: String, user: String): de.blinkt.openvpn.VpnProfile {
        val cp = ConfigParser()
        cp.parseConfig(StringReader(body))
        val profile = cp.convertProfile()
            ?: throw IllegalStateException("config parse failed")
        profile.mName = name
        profile.mUsername = user
        profile.mPassword = "nopass"
        // P7（#135）：确定性 UUID=按名称派生——重导入覆盖同一配置文件，
        // 消除随机 UUID 在 :openvpn 进程（vpnlist 跨进程缓存）下的同步窗口（"Used x 101 tries"）
        profile.setUUID(java.util.UUID.nameUUIDFromBytes(("modsafe-profile:" + name).toByteArray()))
        return profile
    }

    private fun importAndConnect(profile: de.blinkt.openvpn.VpnProfile) {
        progress.visibility = View.GONE
        val pm = ProfileManager.getInstance(this)
        // 同名替换：门户确定性命名的旧配置先删再导（决议 Q2：重复扫码不产生重复条目）
        for (old in pm.getProfiles().filter { it.mName == profile.mName }) {
            pm.removeProfile(this, old)
        }
        pm.addProfile(profile)
        ProfileManager.saveProfile(this, profile)
        // #136：必须落盘 vpnlist——addProfile 只改内存、saveProfile 只写序列化文件，
        // 而 removeProfile 会写入不含新 UUID 的清单；:openvpn 进程只认 vpnlist，
        // 漏此步 = 服务进程永远加载不到配置（"Used x 101 tries (-1/x)"、自动连接失败）
        pm.saveProfileList(this)
        val i = Intent(this, LaunchVPN::class.java)
        i.putExtra(LaunchVPN.EXTRA_KEY, profile.getUUID().toString())
        i.putExtra(OpenVPNService.EXTRA_START_REASON, "qr import")
        i.action = Intent.ACTION_MAIN
        startActivity(i)
        finish()
    }

    private fun fail(msg: String) {
        progress.visibility = View.GONE
        retry.visibility = View.VISIBLE
        status.text = msg
    }

    private fun hasAnyProfile(): Boolean =
        ProfileManager.getInstance(this).getProfiles().any { !it.profileDeleted }

    companion object {
        // ADR-3：二维码域名白名单（首启配置的门户域名；未配置=空集=全拒绝，禁止任意 URL 投毒配置）
        private fun allowedHosts(context: android.content.Context): Set<String> =
            de.blinkt.openvpn.core.PortalConfig.allowedHosts(context)
        private val NAME_RE = Pattern.compile("^[A-Za-z0-9_.-]{1,64}$")
        // P5：一次性下载 token（服务端生成的路径段，收紧字符集防路径注入）
        private val TOKEN_RE = Pattern.compile("^[A-Za-z0-9._-]{1,128}$")
        // B 方案：一次性连接 ticket（控制面 randomToken=64 位 hex）
        private val GRANT_RE = Pattern.compile("^[0-9a-fA-F]{16,128}$")
    }
}
