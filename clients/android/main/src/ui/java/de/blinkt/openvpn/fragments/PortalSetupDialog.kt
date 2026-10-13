/*
 * Modsafe 首启配置：门户域名设置（全屏不可取消对话框）。
 * 未配置门户域名时由 MainActivity 弹出；配置前所有门户相关功能拒绝服务。
 */
package de.blinkt.openvpn.fragments

import android.app.Dialog
import android.os.Bundle
import android.text.InputType
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.fragment.app.DialogFragment
import de.blinkt.openvpn.R
import de.blinkt.openvpn.core.PortalConfig

class PortalSetupDialog : DialogFragment() {

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val ctx = requireContext()
        val view = LayoutInflater.from(ctx).inflate(R.layout.portal_setup, null)
        val edit = view.findViewById<EditText>(R.id.portal_url)
        edit.inputType = InputType.TYPE_TEXT_VARIATION_URI

        val dialog = android.app.AlertDialog.Builder(ctx)
            .setTitle(R.string.portal_setup_title)
            .setMessage(R.string.portal_setup_message)
            .setView(view)
            .setCancelable(false)
            .setPositiveButton(R.string.portal_setup_save, null)
            .create()

        dialog.setOnShowListener {
            val btn = dialog.getButton(android.app.AlertDialog.BUTTON_POSITIVE)
            btn.setOnClickListener {
                val url = edit.text.toString().trim()
                if (isValidPortalUrl(url)) {
                    PortalConfig.setPortalUrl(ctx, url)
                    Toast.makeText(ctx, R.string.portal_setup_saved, Toast.LENGTH_SHORT).show()
                    dismiss()
                } else {
                    Toast.makeText(ctx, R.string.portal_setup_invalid, Toast.LENGTH_LONG).show()
                }
            }
        }
        return dialog
    }

    private fun isValidPortalUrl(url: String): Boolean {
        if (url.isBlank()) return false
        val uri = android.net.Uri.parse(url)
        return uri.scheme == "https" && !uri.host.isNullOrBlank()
    }
}
