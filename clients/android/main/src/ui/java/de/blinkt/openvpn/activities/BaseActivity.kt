/*
 * Copyright (c) 2012-2015 Arne Schwabe
 * Distributed under the GNU GPL v2 with additional terms. For full terms see the file doc/LICENSE.txt
 */
package de.blinkt.openvpn.activities

import android.app.UiModeManager
import android.content.Context
import android.content.Intent
import android.content.res.Configuration
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.widget.Toast
import androidx.activity.SystemBarStyle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updateLayoutParams
import androidx.core.view.updatePadding
import androidx.lifecycle.Lifecycle
import de.blinkt.openvpn.R
import de.blinkt.openvpn.core.ConnectionStatus
import de.blinkt.openvpn.core.GlobalPreferences
import de.blinkt.openvpn.core.LocaleHelper
import de.blinkt.openvpn.core.VpnStatus

abstract class BaseActivity : AppCompatActivity(), VpnStatus.StateListener {
    val isAndroidTV: Boolean
        get() {
            val uiModeManager = getSystemService(UI_MODE_SERVICE) as UiModeManager
            return uiModeManager.currentModeType == Configuration.UI_MODE_TYPE_TELEVISION
        }

    private var mAuthDialog: androidx.appcompat.app.AlertDialog? = null

    /**
     * P9.2（#139）：认证弹框下沉到公共基类——任何页面（配置列表/连接日志/设置等）处于
     * 前台时，连接进入「等待用户认证」即弹框提醒，点「打开浏览器」完成认证。
     * 弹框由可见 Activity 发起，不受 Android 后台启动限制（服务进程拉页面会被静默拦截，
     * #137/#138 两次教训）；子类若重写 updateState 必须调 super。
     */
    open override fun updateState(
        state: String?,
        logmessage: String?,
        localizedResId: Int,
        level: ConnectionStatus?,
        intent: Intent?
    ) {
        if (level == ConnectionStatus.LEVEL_WAITING_FOR_USER_INPUT) {
            // 仅浏览器认证类意图弹框；CR_TEXT（CredentialsPopup）/VPN 权限（LaunchVPN）各有自己的 UI
            if (intent == null || Intent.ACTION_VIEW != intent.action) return
            runOnUiThread {
                if (isFinishing || isDestroyed ||
                    !lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED) ||
                    mAuthDialog?.isShowing == true
                ) return@runOnUiThread
                mAuthDialog = androidx.appcompat.app.AlertDialog.Builder(this)
                    .setTitle(R.string.modsafe_auth_required_title)
                    .setMessage(R.string.modsafe_auth_required_msg)
                    .setPositiveButton(R.string.modsafe_auth_open) { _, _ ->
                        try {
                            startActivity(intent)
                        } catch (e: Exception) {
                            Toast.makeText(this, R.string.portal_open_fail, Toast.LENGTH_SHORT).show()
                        }
                    }
                    .setNegativeButton(R.string.cancel, null)
                    .show()
            }
        } else {
            // 状态离开等待态（认证完成/断开）自动收起弹框
            runOnUiThread {
                mAuthDialog?.dismiss()
                mAuthDialog = null
            }
        }
    }

    open override fun setConnectedVPN(uuid: String?) {
    }

    override fun onResume() {
        super.onResume()
        // addStateListener 去重且注册即回调当前状态（等待中的认证回页面会补弹）
        VpnStatus.addStateListener(this)
    }

    override fun onPause() {
        super.onPause()
        VpnStatus.removeStateListener(this)
        mAuthDialog?.dismiss()
        mAuthDialog = null
    }

    protected fun checkMinimalUIDisabled() {
        if (GlobalPreferences.getMinimalUi()) {
            Toast.makeText(this, R.string.minimal_ui_not_available, Toast.LENGTH_LONG).show()
            finish()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        if (isAndroidTV) {
            requestWindowFeature(Window.FEATURE_OPTIONS_PANEL)
        }
        this.enableEdgeToEdge(SystemBarStyle.dark(R.color.primary_dark))
        super.onCreate(savedInstanceState)
    }

    fun setUpEdgeEdgeInsetsListener(
        rootView: View,
        contentViewId: Int = R.id.root_linear_layout,
        setupBottom: Boolean = true
    ) {
        val contentView = rootView.findViewById<View>(contentViewId)

        ViewCompat.setOnApplyWindowInsetsListener(contentView) { v, windowInsets ->
            val insets =
                windowInsets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            val statusbarbg = findViewById<View>(R.id.statusbar_background);

            val statusBarInsets = windowInsets.getInsets(WindowInsetsCompat.Type.statusBars())

            statusbarbg.layoutParams.height = statusBarInsets.top


            v.updateLayoutParams<ViewGroup.MarginLayoutParams> {
                topMargin = insets.top
            }

            v.updatePadding(
                left = insets.left,
                right = insets.right,
            )
            if (setupBottom) {
                v.updatePadding(bottom = insets.bottom)
                WindowInsetsCompat.CONSUMED
            } else {
                windowInsets
            }
        }
    }

    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(LocaleHelper.updateResources(base))
    }

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        LocaleHelper.onConfigurationChange(this)
    }
}
