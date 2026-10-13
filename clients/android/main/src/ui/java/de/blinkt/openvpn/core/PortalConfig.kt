/*
 * Modsafe 门户域名配置：首次启动时由用户/管理员配置，不写死。
 * 存储于默认 SharedPreferences；未配置时所有门户相关功能拒绝服务（安全默认）。
 */
package de.blinkt.openvpn.core

import android.content.Context
import android.net.Uri

object PortalConfig {
    private const val PREF_PORTAL_URL = "portal_url"

    fun getPortalUrl(context: Context): String =
        Preferences.getDefaultSharedPreferences(context).getString(PREF_PORTAL_URL, "") ?: ""

    fun setPortalUrl(context: Context, url: String) {
        Preferences.getDefaultSharedPreferences(context).edit()
            .putString(PREF_PORTAL_URL, url.trim()).apply()
    }

    fun isConfigured(context: Context): Boolean = getPortalUrl(context).isNotBlank()

    /**
     * 允许的门户 host（从未配置的门户 URL 解析）。
     * 未配置 → null（调用方应拒绝所有请求，安全默认）。
     */
    fun allowedHost(context: Context): String? {
        val url = getPortalUrl(context)
        if (url.isBlank()) return null
        return Uri.parse(url).host
    }

    /**
     * 门户 URL 白名单（供扫码导入 / WebAuth / 升级检查使用）。
     * 未配置 → 空集（全拒绝）。
     */
    fun allowedHosts(context: Context): Set<String> {
        val host = allowedHost(context) ?: return emptySet()
        return setOf(host)
    }
}
