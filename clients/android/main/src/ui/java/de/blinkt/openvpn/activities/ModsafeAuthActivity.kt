package de.blinkt.openvpn.activities

import android.annotation.SuppressLint
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import de.blinkt.openvpn.R

/**
 * P2：WEB_AUTH 内嵌容器（ANDROID-QR-AUTH-DESIGN §二/ADR-4）。
 * 只渲染 modsafe 白名单域名；IM 授权域名（钉钉/企微/飞书）按包名锚点拉起对应 App，
 * 三级分发：setPackage 拉起 → 系统浏览器兜底 → inline 渲染（保底可走本地账号登录）。
 * 认证完成在服务端带内闭环（oa2 回调 → 插件放行 → 隧道自连），本页识别到回调成功页即自动关闭。
 */
class ModsafeAuthActivity : BaseActivity() {

    private lateinit var web: WebView
    private var finishedByCallback = false

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val url = intent?.getStringExtra(EXTRA_URL) ?: intent?.dataString
        if (url == null) {
            finish()
            return
        }
        web = WebView(this)
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.webViewClient = ModsafeWebClient()
        setContentView(web)
        if (savedInstanceState == null) {
            // P9（#137）：弹框提醒需要浏览器认证（系统语言自动中英文）；确认后加载认证页
            AlertDialog.Builder(this)
                .setTitle(R.string.modsafe_auth_required_title)
                .setMessage(R.string.modsafe_auth_required_msg)
                .setPositiveButton(R.string.modsafe_auth_open) { _, _ -> web.loadUrl(url) }
                .setNegativeButton(R.string.cancel) { _, _ -> finish() }
                .setCancelable(false)
                .show()
        } else {
            // 进程重建：直接恢复加载，避免停在空白页
            web.loadUrl(url)
        }
    }

    private inner class ModsafeWebClient : WebViewClient() {
        override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
            return handleUrl(request.url)
        }

        @Deprecated("Deprecated in Java")
        override fun shouldOverrideUrlLoading(view: WebView, url: String): Boolean {
            return handleUrl(Uri.parse(url))
        }

        override fun onPageFinished(view: WebView, url: String) {
            // 成功页识别：oa2 回调落在 modsafe 域名即认证完成（隧道随后自动上线），延迟一拍关闭
            if (!finishedByCallback && isCallbackUrl(url)) {
                finishedByCallback = true
                Toast.makeText(this@ModsafeAuthActivity, R.string.auth_complete, Toast.LENGTH_SHORT).show()
                web.postDelayed({ finish() }, 1500)
            }
        }
    }

    private fun handleUrl(u: Uri): Boolean {
        val scheme = u.scheme ?: ""
        val host = u.host ?: ""
        // 非http(s)：IM 自有 scheme 直接拉起，其余交给系统
        if (scheme != "https" && scheme != "http") {
            if (scheme in IM_SCHEMES) return dispatch(u, null)
            return false
        }
        // modsafe 域名：页内渲染；命中回调即由 onPageFinished 收尾
        if (host in MODSAFE_HOSTS) return false
        // IM 授权域名：按锚点包名拉起对应 App（决议：拉起钉钉/企业微信/飞书认证）
        IM_HOST_PACKAGES[host]?.let { pkg ->
            if (dispatch(u, pkg)) return true
        }
        // 兜底①：系统浏览器（浏览器可派发 app-link）
        if (dispatch(u, null)) return true
        // 兜底②：inline 渲染（保底可走本地账号/密码登录路径）
        return false
    }

    private fun dispatch(u: Uri, pkg: String?): Boolean {
        return try {
            val i = Intent(Intent.ACTION_VIEW, u)
            pkg?.let { i.setPackage(it) }
            startActivity(i)
            true
        } catch (e: ActivityNotFoundException) {
            false
        }
    }

    private fun isCallbackUrl(url: String): Boolean {
        val u = Uri.parse(url)
        return u.host in MODSAFE_HOSTS && u.path?.contains("/callback") == true
    }

    override fun onBackPressed() {
        if (::web.isInitialized && web.canGoBack()) web.goBack() else super.onBackPressed()
    }

    companion object {
        const val EXTRA_URL = "de.blinkt.openvpn.MODSAFE_AUTH_URL"
        // OpenVPNService（main 层）经隐式 Intent 启动本 activity（ui 层），action 见 intent-filter
        const val ACTION_AUTH = "de.blinkt.openvpn.MODSAFE_AUTH"

        // ADR-4：IM 授权域名 → App 包名锚点
        private val IM_HOST_PACKAGES = mapOf(
            "login.dingtalk.com" to "com.alibaba.android.rimet",
            "login.work.weixin.qq.com" to "com.tencent.wework",
            "open.feishu.cn" to "com.ss.android.lark",
        )
        private val IM_SCHEMES = setOf("dingtalk", "wework", "feishu", "lark")
        private val MODSAFE_HOSTS = setOf("192.168.0.180", "192.168.0.140", "ac.t.isjue.cn")
    }
}
