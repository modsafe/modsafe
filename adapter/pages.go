package main

// HTML 模板（OA2 品牌模板 + 登录页骨架）逐字移植自 Python 版；
// 差异：BRAND_PAGE 中 CSS content:"\203a" 在 Python 源码里被八进制转义损坏为 U+0083，
// Go 原始字符串保留字面 \203a —— 浏览器按 CSS 转义解析为「›」，为上游本意。

import (
	"html"
	"net/url"
	"os"
	"strings"
	"time"
)

const OA2_TEMPLATE_STR = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ .title }} · __PRODUCT_NAME__</title>
<style>
:root{--blue:#1D4ED8;--ink:#1d1d1f;--ink-2:#6e6e73;--ink-3:#7a7a7a;
  --hairline:#e0e0e0;--paper:#f5f5f7;--card:#ffffff;--red:#d70015;--green:#34c759}
*{box-sizing:border-box;-webkit-font-smoothing:antialiased}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text",
  "PingFang SC","Helvetica Neue","Microsoft YaHei","Segoe UI",sans-serif;
  background:var(--paper);min-height:100vh;display:flex;flex-direction:column;
  align-items:center;color:var(--ink)}
.brand{display:flex;align-items:center;gap:14px;padding:48px 0 6px}
.logo{width:42px;height:42px;border-radius:11px;background:#EFF6FF;color:#fff;
  display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:600}
.company{font-size:19px;font-weight:600;letter-spacing:-.37px;line-height:1.2}
.product{font-size:13px;color:var(--ink-3);letter-spacing:.5px;margin-top:1px}
main{background:var(--card);border:1px solid var(--hairline);border-radius:18px;
  padding:44px 40px 38px;margin-top:24px;max-width:440px;width:88%;text-align:center}
.icon{width:64px;height:64px;border-radius:50%;margin:0 auto 18px;display:flex;
  align-items:center;justify-content:center}
.icon-ok{background:var(--green)}
.icon-err{background:var(--red)}
h1{font-size:28px;font-weight:600;letter-spacing:-.28px;margin:0 0 10px;line-height:1.1}
p{color:var(--ink-2);font-size:17px;line-height:1.47;margin:0}
.err-id{color:var(--ink-3);font-size:12px;margin-top:10px;letter-spacing:-.12px}
.ready{margin-top:22px;color:var(--ink-3);font-size:14px}
.profile-form{margin-top:22px;display:flex;flex-direction:column;gap:10px}
.profile-button{padding:12px 22px;border:1px solid var(--blue);border-radius:9999px;
  background:var(--card);color:var(--blue);font-size:17px;font-family:inherit;cursor:pointer;
  transition:transform .1s ease}
.profile-button:active{transform:scale(.95)}
footer{margin-top:auto;padding:30px 0 26px;font-size:12px;color:var(--ink-3)}
</style></head>
<body>
<div class="brand"><div class="logo"><svg viewBox="0 0 120 120" width="100%" height="100%"><polygon points="20,34 86,34 100,20 34,20" fill="#3B82F6"/><polygon points="86,34 100,20 100,86 86,100" fill="#12307A"/><rect x="20" y="34" width="66" height="66" fill="#1D4ED8"/><path d="M37 44 H69 C71.21 44 73 45.79 73 48 V67 C73 78 66 84 53 89 C40 84 33 78 33 67 V48 C33 45.79 34.79 44 37 44 Z" fill="#FFFFFF"/></svg></div>
  <div><div class="company">__COMPANY_NAME__</div>
  <div class="product">__PRODUCT_NAME__</div></div></div>
<main>
  {{- if .errorID }}
  <div class="icon icon-err"><svg width="30" height="30" viewBox="0 0 24 24" fill="none">
    <path d="M12 7v6" stroke="#fff" stroke-width="2.4" stroke-linecap="round"/>
    <circle cx="12" cy="16.8" r="1.4" fill="#fff"/></svg></div>
  {{- else }}
  <div class="icon icon-ok"><svg width="30" height="30" viewBox="0 0 24 24" fill="none">
    <path d="M5.5 12.5l4.2 4.2L18.5 8" stroke="#fff" stroke-width="2.4"
      stroke-linecap="round" stroke-linejoin="round"/></svg></div>
  {{- end }}
  <h1 data-i18n>{{ .title }}</h1>
  {{- if .message }}
  <p data-i18n>{{ .message }}</p>
  {{- end }}
  {{- if .errorID }}
  <p class="err-id">Error ID: {{ .errorID }}</p>
  {{- end }}
  {{- /* #61：拒绝页"切换账号"逃生口——证书与扫码人不匹配死循环时，一键清除两个
       身份会话（门户 portal_sess + 免扫码 web_sess，与门户退出同款端点/同域调用），
       下次连接自然弹出扫码页由用户选择正确账号。仅清身份 cookie，不动其他缓存。 */}}
  {{- if .errorID }}
  <p style="margin-top:18px">
    <button id="switch-user-btn" class="btn-primary" style="display:none;cursor:pointer"
      >切换账号重新登录</button>
    <span id="switch-user-done" style="display:none;font-size:14px"></span>
  </p>
  {{- end }}
  {{- if .clientConfigProfiles }}
  <div class="profile-buttons">
    <form method="POST" action="./profile-submit" class="profile-form">
      <input type="hidden" name="token" value="{{ .token }}">
      {{- range .clientConfigProfiles }}
      <input class="profile-button" type="submit" name="profile" value="{{ . }}">
      {{- end }}
    </form>
  </div>
  {{- end }}
  <script>
  (function(){
    // #61：拒绝文案带自助排查引导（覆盖 账号停用/证书与账号不匹配/其他校验失败
    // —— oa2 错误页不区分失败类型是防探测的安全设计，故用通用可能原因列表）
    var M={"Access granted":"登录成功",
           "You can close this window now.":"此窗口现在可以关闭了。",
           "Access denied":"认证未通过",
           "Please contact your administrator.":"可能原因：账号已被停用，或本配置文件与登录账号不匹配。请确认使用本人账号登录，或到员工门户重新下载配置文件；仍有问题请联系管理员。"};
    function tr(s){return M[s]||null}
    var isZh=/^zh/i.test(navigator.language||navigator.userLanguage||"");
    var isDenied=false;
    if(isZh){
      document.querySelectorAll("[data-i18n]").forEach(function(el){
        var t=tr(el.textContent.trim()); if(t)el.textContent=t;});
      var parts=document.title.split(" · ");
      var dt=tr(parts[0]); if(dt)document.title=dt+" · "+parts.slice(1).join(" · ");
      var h1=document.querySelector("h1[data-i18n]");
      isDenied=!!(h1&&h1.textContent.indexOf("认证未通过")>=0);
    }else{
      var h1e=document.querySelector("h1[data-i18n]");
      isDenied=!!(h1e&&h1e.textContent.indexOf("Access denied")>=0);
    }
    // #61：拒绝页"切换账号"——清除两个身份会话（与门户退出同款端点，同域调用），
    // 下次连接弹出扫码页由用户选择正确账号；仅清身份 cookie，不动其他缓存
    var btn=document.getElementById("switch-user-btn"),done=document.getElementById("switch-user-done");
    if(btn&&isDenied){
      btn.style.display="inline-block";
      btn.textContent=isZh?"切换账号重新登录":"Switch account";
      btn.onclick=function(){
        btn.disabled=true;btn.textContent=isZh?"正在切换…":"Switching…";
        fetch("/api/v1/self/logout",{method:"POST",credentials:"same-origin"}).catch(function(){})
          .then(function(){return fetch("/logout-web-sess",{credentials:"same-origin"}).catch(function(){})})
          .then(function(){
            btn.style.display="none";
            done.style.display="inline";
            done.textContent=isZh
              ?"已清除本浏览器的登录身份。请先暂停 VPN 客户端的自动重连，再重新连接并用配置文件所属人的账号完成登录。"
              :"Browser identity cleared. Pause VPN auto-reconnect, then reconnect and sign in with the account that owns this profile.";
          });
      };
    }
  })();
  </script>
<script>
(function(){
  // #140/#142：认证成功页自动返回 App 并尽力关闭标签页——仅成功页触发（错误页/配置下载页不动）；
  // 深链 modsafe://auth-complete 由客户端 AuthReturnActivity 接收。window.close() 对
  // "外部应用(VIEW intent)打开的标签页"有效；普通打开的关不掉→显示"可手动关闭"兜底提示。
  var h=document.querySelector("h1[data-i18n]");
  var ok=document.querySelector(".icon-ok")!==null;
  var hasErr=document.querySelector(".err-id")!==null;
  var hasProfiles=document.querySelector(".profile-buttons")!==null;
  var okTitle=h!==null&&(h.textContent.indexOf("Access granted")>=0||h.textContent.indexOf("登录成功")>=0);
  if(!(ok&&okTitle&&!hasErr&&!hasProfiles))return;
  var isZh=/^zh/i.test(navigator.language||"");
  var m=document.querySelector("main");if(!m)return;
  var hint=document.createElement("p");
  hint.style.cssText="margin-top:20px;color:#6e6e73;font-size:14px";
  hint.textContent=isZh?"认证成功，正在自动返回模方安全…":"Authentication successful. Returning to the app…";
  var a=document.createElement("a");a.href="modsafe://auth-complete";
  a.style.cssText="display:inline-block;margin-top:14px;padding:12px 28px;border-radius:9999px;background:#1D4ED8;color:#fff;font-size:16px;text-decoration:none";
  a.textContent=isZh?"返回模方安全客户端":"Return to app";
  m.appendChild(hint);m.appendChild(a);
  var closeHint=document.createElement("p");
  closeHint.style.cssText="margin-top:10px;color:#7a7a7a;font-size:12px;display:none";
  closeHint.textContent=isZh?"本页面可以手动关闭了":"This page can be closed now";
  m.appendChild(closeHint);
  var done=false;
  function backToApp(){
    if(done)return;done=true;
    window.location.href="modsafe://auth-complete";
    setTimeout(function(){
      window.close();
      setTimeout(function(){
        if(!window.closed){
          closeHint.style.display="block";
          hint.textContent=isZh?"认证成功，可返回模方安全查看连接状态":"Authenticated. Check the connection status in the app";
        }
      },600);
    },400);
  }
  a.onclick=function(ev){ev.preventDefault();backToApp();};
  setTimeout(backToApp,2500);
})();
</script>
</main>
<footer>© __YEAR__ __COMPANY_NAME__ · __FOOTER_TEXT__</footer>
</body></html>
`

const BRAND_PAGE = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>登录 · __PRODUCT_NAME__</title>
<style>
:root{--blue:#1D4ED8;--blue-focus:#3B82F6;--ink:#1d1d1f;--ink-2:#6e6e73;
  --ink-3:#7a7a7a;--hairline:#e0e0e0;--paper:#f5f5f7;--card:#ffffff;--red:#d70015}
*{box-sizing:border-box;-webkit-font-smoothing:antialiased}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text",
  "PingFang SC","Helvetica Neue","Microsoft YaHei","Segoe UI",sans-serif;
  background:var(--paper);min-height:100vh;display:flex;flex-direction:column;
  align-items:center;color:var(--ink)}
.brand{display:flex;align-items:center;gap:14px;padding:44px 0 6px}
.logo{width:42px;height:42px;border-radius:11px;background:#EFF6FF;color:#fff;
  display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:600}
.company{font-size:19px;font-weight:600;letter-spacing:-.37px;line-height:1.2}
.product{font-size:13px;color:var(--ink-3);letter-spacing:.5px;margin-top:1px}
main{background:var(--card);border:1px solid var(--hairline);border-radius:18px;
  padding:38px 34px 34px;margin-top:22px;max-width:400px;width:88%}
h2{font-size:21px;font-weight:600;letter-spacing:-.37px;margin:0 0 20px;text-align:center}
.idp{display:flex;align-items:center;gap:14px;width:100%;margin:10px 0;padding:13px 16px;
  border:1px solid var(--hairline);border-radius:18px;background:var(--card);color:var(--ink);
  font-size:17px;font-family:inherit;text-align:left;cursor:pointer;text-decoration:none;
  transition:background .15s ease,transform .1s ease}
.idp:hover{background:var(--paper)}
.idp:active{transform:scale(.98)}
.idp::after{content:"\203a";margin-left:auto;color:var(--ink-3);font-size:20px}
.ic{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;
  border-radius:8px;background:#1D4ED8;color:#fff;font-weight:600;font-size:13px;flex:none}
.btn-primary{display:block;width:100%;margin:18px 0 0;padding:12px 22px;border:none;
  border-radius:9999px;background:var(--blue);color:#fff;font-size:17px;font-family:inherit;
  text-align:center;cursor:pointer;text-decoration:none;transition:transform .1s ease}
.btn-primary:active{transform:scale(.95)}
.btn-primary:focus-visible,.idp:focus-visible{outline:2px solid var(--blue-focus);outline-offset:2px}
.hint{color:var(--ink-3);font-size:14px;line-height:1.43;text-align:center;margin:12px 0 0}
.jump-progress{height:2px;border-radius:2px;background:var(--hairline);margin-top:14px;overflow:hidden}
.jump-progress i{display:block;height:100%;background:var(--blue);animation:jmp 3s linear forwards}
@keyframes jmp{from{width:0}to{width:100%}}
.sep{height:1px;background:var(--hairline);margin:22px 0 0}
.link{display:block;text-align:center;font-size:17px;color:var(--blue);text-decoration:none;
  padding:12px 0 0;cursor:pointer}
label{font-size:14px;color:var(--ink-2);display:block;margin:16px 0 6px}
input{width:100%;padding:0 18px;border:1px solid #d2d2d7;border-radius:9999px;font-size:17px;
  font-family:inherit;background:var(--card);color:var(--ink);height:44px;appearance:none}
input:focus{border-color:var(--blue);outline:none}
button{width:100%;margin-top:22px;padding:12px 22px;background:var(--blue);color:#fff;border:none;
  border-radius:9999px;font-size:17px;font-family:inherit;cursor:pointer;transition:transform .1s ease}
button:active{transform:scale(.95)}
.err{color:var(--red);font-size:14px;margin:14px 0 0;text-align:center;line-height:1.43}
footer{margin-top:auto;padding:30px 0 26px;font-size:12px;color:var(--ink-3);letter-spacing:-.12px}
</style></head>
<body>
<div class="brand"><div class="logo"><svg viewBox="0 0 120 120" width="100%" height="100%"><polygon points="20,34 86,34 100,20 34,20" fill="#3B82F6"/><polygon points="86,34 100,20 100,86 86,100" fill="#12307A"/><rect x="20" y="34" width="66" height="66" fill="#1D4ED8"/><path d="M37 44 H69 C71.21 44 73 45.79 73 48 V67 C73 78 66 84 53 89 C40 84 33 78 33 67 V48 C33 45.79 34.79 44 37 44 Z" fill="#FFFFFF"/></svg></div>
  <div><div class="company">__COMPANY_NAME__</div>
  <div class="product">__PRODUCT_NAME__</div></div></div>
<main>
__MAIN_CONTENT__
</main>
<footer>© __YEAR__ __COMPANY_NAME__ · __FOOTER_TEXT__</footer>
<script>
/* i18n（#67）：英文浏览器环境自动翻译跳转/选择/本地登录页文案（zh 默认原文）。
   文本节点映射替换——MAIN_CONTENT 动态注入无需打标记；拼接串按前缀匹配。 */
(function(){
  if(!/^en/i.test(navigator.language||navigator.userLanguage||"")) return;
  var M={
    "选择登录方式":"Choose a sign-in method",
    "本地账号登录":"Local account sign-in",
    "该登录方式未启用":"This sign-in method is not enabled",
    "该登录方式已被管理员禁用":"This sign-in method has been disabled by your administrator",
    "state 无效或过期":"Invalid or expired state",
    "请重新发起 VPN 连接":"Please start the VPN connection again",
    "账号":"Account",
    "密码":"Password",
    "登 录":"Sign in",
    "3 秒后自动进入":"Continuing automatically in 3 seconds",
    "模拟扫码登录":"Mock QR sign-in",
    /* #69：LDAP/本地登录的服务端错误消息（err_msg 查询参数渲染进 .err 元素） */
    "账号或密码错误":"Incorrect account or password",
    "请输入账号和密码":"Please enter your account and password",
    "认证服务不可用":"Authentication service unavailable",
    "控制平面不可用":"Control plane unavailable",
    /* §22 SAML 登录页与错误页 */
    "企业 SSO（SAML）":"Enterprise SSO (SAML)",
    "登录失败":"sign-in failed"
  };
  var P=[["立即进入 ","Continue to "],[" 登录"," sign-in"]];
  var w=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT,null);
  var n;
  while((n=w.nextNode())){
    var s=n.nodeValue.trim();
    if(!s) continue;
    if(M[s]!==undefined){n.nodeValue=n.nodeValue.replace(s,M[s]);continue;}
    for(var i=0;i<P.length;i++){
      if(s.indexOf(P[i][0])===0){n.nodeValue=n.nodeValue.replace(P[i][0],P[i][1]);break;}
    }
  }
  if(/^登录/.test(document.title)) document.title=document.title.replace(/^登录/,"Sign in");
})();
</script>
</body></html>
`

// brandHTML：品牌字段进 HTML 模板前统一转义（branding.json/管理台可写，
// 登录页与 OA2 模板为服务端渲染——不转义则品牌字段即存储型 XSS 注入点）
func brandHTML(s string) string { return html.EscapeString(s) }

func brandPage(mainContent string) string {
	b := loadBranding()
	out := BRAND_PAGE
	out = replaceAll(out, "__COMPANY_NAME__", brandHTML(mStr(b, "company_name")))
	short := mStr(b, "company_name")
	if short != "" {
		short = short[:1]
	} else {
		short = "M"
	}
	out = replaceAll(out, "__COMPANY_SHORT__", brandHTML(short))
	out = replaceAll(out, "__PRODUCT_NAME__", brandHTML(mStr(b, "product_name")))
	out = replaceAll(out, "__FOOTER_TEXT__", brandHTML(mStr(b, "footer_text")))
	out = replaceAll(out, "__YEAR__", time.Now().Format("2006"))
	out = replaceAll(out, "__MAIN_CONTENT__", mainContent)
	return out
}

func replaceAll(s, old, new string) string { return strings.ReplaceAll(s, old, new) }

func writeFileRaw(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

// renderOA2Template：品牌联动写 oa2 模板（启动与 /admin/branding 调用）
func renderOA2Template(cfg map[string]any) {
	short := mStr(cfg, "company_name")
	if short != "" {
		short = short[:1]
	} else {
		short = "M"
	}
	tpl := OA2_TEMPLATE_STR
	tpl = replaceAll(tpl, "__COMPANY_NAME__", brandHTML(mStr(cfg, "company_name")))
	tpl = replaceAll(tpl, "__COMPANY_SHORT__", brandHTML(short))
	tpl = replaceAll(tpl, "__PRODUCT_NAME__", brandHTML(mStr(cfg, "product_name")))
	tpl = replaceAll(tpl, "__FOOTER_TEXT__", brandHTML(mStr(cfg, "footer_text")))
	tpl = replaceAll(tpl, "__YEAR__", time.Now().Format("2006"))
	_ = writeFileRaw(OA2_TEMPLATE, tpl)
}

// localEntryHTML：本地账号兜底入口（§18）：local_auth_enabled 且未隐藏时渲染
func localEntryHTML(cpCfg map[string]any, oa2Redirect, state, nonce string) string {
	if oa2Redirect == "" {
		return ""
	}
	localOn, _ := cpCfg["local_auth_enabled"].(bool)
	if cpCfg["local_auth_enabled"] == nil {
		localOn = true // Python: cp_cfg.get("local_auth_enabled", True)
	}
	hide := mBool(cpCfg, "hide_local_link")
	if !localOn || hide {
		return ""
	}
	qs := url.Values{}
	qs.Set("provider", "local")
	qs.Set("redirect_uri", oa2Redirect)
	qs.Set("state", state)
	qs.Set("nonce", nonce)
	qs.Set("response_type", "code")
	qs.Set("scope", "openid")
	href := "/authorize?" + qs.Encode()
	return `<div class="sep"></div>` +
		`<a href="` + href + `" onclick="try{clearTimeout(_jt)}catch(e){}" ` +
		`class="link">本地账号登录</a>`
}
