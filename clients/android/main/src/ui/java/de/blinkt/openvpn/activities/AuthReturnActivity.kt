package de.blinkt.openvpn.activities

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import de.blinkt.openvpn.R

/**
 * P10（#140）：浏览器认证成功后自动返回 App。
 * 服务端 oa2 成功页（Access granted）JS 延时跳转 modsafe://auth-complete → 系统拉起本
 * 透明跳板 → 带回应用任务栈后立即 finish（栈顶回归用户此前所在页面）。
 * 若应用任务已不存在（被杀），先拉起主界面再退场，避免跳回浏览器。
 */
class AuthReturnActivity : BaseActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (isTaskRoot) {
            startActivity(Intent(this, MainActivity::class.java))
        }
        Toast.makeText(this, R.string.auth_complete, Toast.LENGTH_SHORT).show()
        finish()
    }
}
