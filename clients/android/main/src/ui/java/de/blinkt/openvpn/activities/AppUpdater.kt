package de.blinkt.openvpn.activities

import android.app.Activity
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.core.content.FileProvider
import de.blinkt.openvpn.R
import de.blinkt.openvpn.core.Preferences
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/**
 * P6（2026-10-07）：应用内升级——检查版本清单 → 弹窗确认 → 后台下载 → sha256+签名双重校验 → 拉起系统安装。
 * 版本清单 = 下载中心静态 JSON（发布脚本 product-design/publish-apk.py 生成）：
 *   {versionCode, versionName, url, sha256, updatedAt}
 * 安全校验三道：feed/APK 仅接受白名单域（https 硬校验）；下载流式算 sha256 与 feed 比对；
 * 下载包签名证书与本应用在签证书比对（防清单/源被替换后装入异签包）。
 * "自动升级"边界：PackageInstaller MODE_FULL_INSTALL 必经系统安装确认弹窗（Android 安全模型），
 * 应用做到自动检查+自动下载+自动拉起，最后一步由用户点确认。
 */
object AppUpdater {

    private const val FEED_PATH = "/launcher/modsafe-android.json"
    private const val PREF_LAST_CHECK = "lastUpdateCheckAt"
    private const val CHECK_INTERVAL_MS = 6 * 3600 * 1000L
    // 与 QrImportActivity 同口径：仅首启配置的门户域名可下发升级（未配置=空集=全拒绝）
    private fun allowedHosts(context: android.content.Context): Set<String> =
        de.blinkt.openvpn.core.PortalConfig.allowedHosts(context)

    private class Latest(
        val versionCode: Int,
        val versionName: String,
        val url: String,
        val sha256: String,
    )

    /** 自动检查（6h 节流）与手动检查（force=true）共用入口；仅在新版本存在时打扰用户。 */
    fun maybeCheck(activity: Activity, force: Boolean) {
        val prefs = Preferences.getDefaultSharedPreferences(activity)
        val last = prefs.getLong(PREF_LAST_CHECK, 0L)
        if (!force && System.currentTimeMillis() - last < CHECK_INTERVAL_MS) return
        prefs.edit().putLong(PREF_LAST_CHECK, System.currentTimeMillis()).apply()

        val feedUrl = de.blinkt.openvpn.core.PortalConfig.getPortalUrl(activity) + FEED_PATH
        Thread {
            try {
                val latest = fetchFeed(feedUrl, activity)
                if (latest.versionCode <= currentVersionCode(activity)) {
                    if (force) {
                        // Toast 必须在主线程（#135：后台线程直接 toast 会崩 Looper.prepare）
                        runUi(activity) { uiToast(activity, activity.getString(R.string.update_latest)) }
                    }
                    return@Thread
                }
                runUi(activity) { offer(activity, latest) }
            } catch (e: Exception) {
                if (force) {
                    runUi(activity) {
                        uiToast(activity, activity.getString(R.string.update_check_fail, e.localizedMessage ?: ""))
                    }
                }
            }
        }.start()
    }

    private fun fetchFeed(feedUrl: String, activity: Activity): Latest {
        val uri = Uri.parse(feedUrl)
        // 白名单域 + https + 固定路径，防任意源下发升级（同 deep link 校验口径）
        if (uri.scheme != "https" || (uri.host ?: "") !in allowedHosts(activity)) {
            throw IllegalStateException("untrusted feed source")
        }
        val client = OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .build()
        client.newCall(Request.Builder().url(feedUrl).build()).execute().use { resp ->
            if (!resp.isSuccessful) throw IllegalStateException("HTTP ${resp.code}")
            val obj = JSONObject(resp.body?.string() ?: throw IllegalStateException("empty feed"))
            val url = obj.optString("url")
            val u = Uri.parse(url)
            if (u.scheme != "https" || (u.host ?: "") !in allowedHosts(activity) || !(u.path ?: "").startsWith("/launcher/")) {
                throw IllegalStateException("untrusted apk url")
            }
            return Latest(
                versionCode = obj.getInt("versionCode"),
                versionName = obj.optString("versionName"),
                url = url,
                sha256 = obj.optString("sha256"),
            )
        }
    }

    private fun offer(activity: Activity, latest: Latest) {
        if (activity.isFinishing || activity.isDestroyed) return
        AlertDialog.Builder(activity)
            .setTitle(activity.getString(R.string.update_available, latest.versionName))
            .setPositiveButton(R.string.update_now) { _, _ -> downloadAndInstall(activity, latest) }
            .setNegativeButton(R.string.update_later, null)
            .show()
    }

    private fun downloadAndInstall(activity: Activity, latest: Latest) {
        // API 26+：安装未知来源应用需用户一次性授权（系统设置页），授权后重试即可
        if (Build.VERSION.SDK_INT >= 26 &&
            !activity.packageManager.canRequestPackageInstalls()
        ) {
            uiToast(activity, activity.getString(R.string.update_grant_needed))
            activity.startActivity(
                Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:" + activity.packageName))
            )
            return
        }
        val dialog = AlertDialog.Builder(activity)
            .setMessage(R.string.update_downloading)
            .setCancelable(false)
            .show()
        Thread {
            try {
                val file = downloadApk(activity, latest)
                verifySignature(activity, file)
                runUi(activity) {
                    if (!activity.isFinishing && !activity.isDestroyed) dialog.dismiss()
                    install(activity, file)
                }
            } catch (e: Exception) {
                runUi(activity) {
                    if (!activity.isFinishing && !activity.isDestroyed) dialog.dismiss()
                    uiToast(activity, activity.getString(R.string.qr_download_fail, e.localizedMessage ?: ""))
                }
            }
        }.start()
    }

    private fun downloadApk(activity: Activity, latest: Latest): File {
        val dir = activity.getExternalFilesDir("update") ?: activity.filesDir
        val file = File(dir, "update.apk")
        file.parentFile?.mkdirs()
        file.delete()
        val client = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build()
        client.newCall(Request.Builder().url(latest.url).build()).execute().use { resp ->
            if (!resp.isSuccessful) throw IllegalStateException("HTTP ${resp.code}")
            val body = resp.body ?: throw IllegalStateException("empty body")
            val md = MessageDigest.getInstance("SHA-256")
            file.outputStream().use { out ->
                val src = body.byteStream()
                val buf = ByteArray(64 * 1024)
                while (true) {
                    val n = src.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                    md.update(buf, 0, n)
                }
                out.flush()
            }
            if (latest.sha256.isNotEmpty()) {
                val hex = md.digest().joinToString("") { String.format("%02x", it) }
                if (!hex.equals(latest.sha256, ignoreCase = true)) {
                    file.delete()
                    throw IllegalStateException("sha256 mismatch")
                }
            }
            return file
        }
    }

    /** 下载包的签名证书必须与本应用在签证书一致，异签一律拒绝安装。 */
    private fun verifySignature(activity: Activity, file: File) {
        @Suppress("DEPRECATION")
        val pm = activity.packageManager
        @Suppress("DEPRECATION")
        val remote = pm.getPackageArchiveInfo(file.absolutePath, PackageManager.GET_SIGNATURES)
            ?: throw IllegalStateException("not a valid apk")
        @Suppress("DEPRECATION")
        val own = pm.getPackageInfo(activity.packageName, PackageManager.GET_SIGNATURES)
        @Suppress("DEPRECATION")
        val remoteSig = remote.signatures?.firstOrNull()?.toCharsString()
        @Suppress("DEPRECATION")
        val ownSig = own.signatures?.firstOrNull()?.toCharsString()
        if (remoteSig.isNullOrEmpty() || remoteSig != ownSig) {
            file.delete()
            throw IllegalStateException("signature mismatch")
        }
    }

    private fun install(activity: Activity, file: File) {
        if (Build.VERSION.SDK_INT >= 26) {
            installViaSession(activity, file)
        } else {
            // API 23-25 回退：FileProvider + 系统安装器
            val uri = FileProvider.getUriForFile(activity, activity.packageName + ".InstallFileProvider", file)
            val i = Intent(Intent.ACTION_INSTALL_PACKAGE)
                .setDataAndType(uri, "application/vnd.android.package-archive")
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
            activity.startActivity(i)
        }
    }

    private fun installViaSession(activity: Activity, file: File) {
        if (Build.VERSION.SDK_INT < 26) return
        val installer = activity.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
        val sessionId = installer.createSession(params)
        val session = installer.openSession(sessionId)
        try {
            FileInputStream(file).use { input ->
                session.openWrite("modsafe-update.apk", 0, file.length()).use { out ->
                    input.copyTo(out)
                    session.fsync(out)
                }
            }
            val callback = Intent(activity, AppInstallReceiver::class.java)
                .setAction(AppInstallReceiver.ACTION_COMMIT)
            val pi = PendingIntent.getBroadcast(
                activity, sessionId, callback,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
            )
            session.commit(pi.intentSender)
            uiToast(activity, activity.getString(R.string.update_install_pending))
        } finally {
            session.close()
        }
    }

    private fun currentVersionCode(activity: Activity): Int {
        val info = activity.packageManager.getPackageInfo(activity.packageName, 0)
        return if (Build.VERSION.SDK_INT >= 28) info.longVersionCode.toInt() else info.versionCode
    }

    private fun runUi(activity: Activity, block: () -> Unit) {
        activity.runOnUiThread(block)
    }

    private fun uiToast(activity: Activity, msg: String) {
        if (activity.isFinishing || activity.isDestroyed) return
        Toast.makeText(activity, msg, Toast.LENGTH_LONG).show()
    }
}
