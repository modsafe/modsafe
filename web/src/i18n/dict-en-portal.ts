/* 门户英文词典（key=zh 原文）。缺项自动回退中文。 */
export const enPortal: Record<string, string> = {
  // 导航
  '首页': 'Home',
  '设备': 'Devices',
  '统计': 'Usage',
  '下载': 'Download',
  '我的': 'Me',
  '退出': 'Sign out',
  '退出登录': 'Sign out',
  '加载中…': 'Loading…',
  // 身份/通用
  '本地账号': 'Local account',
  '钉钉': 'DingTalk',
  '企业微信': 'WeCom',
  '飞书': 'Feishu',
  'AD 域': 'AD domain',
  '在线': 'Online',
  '已断开': 'Disconnected',
  '断开连接': 'Disconnect',
  '正在断开…': 'Disconnecting…',
  '已断开连接，可重新一键连接。': 'Disconnected. You can one-click connect again.',
  '账号': 'Account',
  '认证方式': 'Sign-in method',
  '密码管理': 'Password',
  '本门户修改': 'Managed in this portal',
  '在企业认证源（钉钉/企微等）修改': 'Managed in your corporate IdP (DingTalk/WeCom etc.)',
  '账号密码由企业认证源统一管理，如需修改请联系所在平台的账号设置。':
    'Your password is managed by the corporate IdP. To change it, use your account settings on that platform.',
  '员工自助服务': 'Self-service',
  '员工门户': 'Employee Portal',
  '请求失败': 'Request failed',
  '下载链接已失效，请重新生成': 'Download link expired, please generate a new one',
  // 首页/通行证
  '接入内部网络': 'Connect to the internal network',
  '未连接': 'Not connected',
  '完成连接': 'Finish setup',
  '正在准备一键连接…': 'Preparing one-click connect…',
  '设备额度已满，请先到「设备」页删除旧设备。':
    'Device quota is full. Please remove an old device on the Devices page first.',
  // 引导
  '三步完成，全程不需要管理员': 'Three steps, no administrator needed',
  '企业扫码用户请从扫码入口进入': 'Corporate scan-code users should sign in via the QR entry',
  '一键接入后全自动；手动导入的，连接时浏览器会弹出企业认证，扫码通过即上线（之后当天免扫码）。':
    'Fully automatic after one-click setup; for manual import, the browser will pop up corporate authentication when connecting — sign in once and stay connected for the day.',
  // 设备
  '我的设备': 'My devices',
  '添加新设备': 'Add a device',
  '正在生成…': 'Generating…',
  '生成我的配置文件': 'Generate my profile',
  '下载我的接入配置': 'Download my access profile',
  '生成一份含个人证书的 .ovpn 文件。链接 5 分钟内有效，只能下载一次，请下载后妥善保存。':
    'Generates a .ovpn file with your personal certificate. The link is valid for 5 minutes, one-time download only — keep the file safe.',
  '导入客户端': 'Import to client',
  '额度已满，先删除一台旧设备': 'Quota full — remove an old device first',
  // 统计
  '近 30 天流量': 'Traffic (last 30 days)',
  '近 30 天 · 绿色为上传，蓝色为下载': 'Last 30 days · green = upload, blue = download',
  '还没有流量记录，连上后这里会出现你的使用情况。':
    'No traffic yet. Your usage will appear here once you connect.',
  '还没有连接记录。': 'No connection history yet.',
  // 密码
  '修改密码': 'Change password',
  '当前密码': 'Current password',
  '新密码（至少 8 位）': 'New password (at least 8 characters)',
  '保存新密码': 'Save new password',
  '正在保存…': 'Saving…',
  '修改后需要重新登录': 'You will need to sign in again after changing',
  // 下载中心
  '一键连接仅支持 Windows。当前设备请下载 .ovpn 配置，手动导入客户端（Linux/macOS/Android 见下载中心）。':
    'One-click connect is Windows-only. On this device, download the .ovpn profile and import it manually (see Download Center for Linux/macOS/Android clients).',
  '未检测到模方安全客户端。请到「下载中心」下载安装 Windows 客户端（已内置连接组件），安装后重新点「一键连接」。':
    'Modsafe client not detected. Download and install the Windows client from the Download Center (helper bundled), then click "Connect" again.',
  '一键接入仅支持 Windows。当前设备请点「下载 .ovpn（手动导入用）」，导入客户端（Linux/macOS/Android 客户端见下载中心）。':
    'One-click setup is Windows-only. On this device, click "Download .ovpn (manual import)" and import it into your client (see Download Center for Linux/macOS/Android).',
  '未检测到模方安全客户端。请到「下载中心」下载安装 Windows 客户端（已内置连接组件），安装后重新点「一键接入」。':
    'Modsafe client not detected. Download and install the Windows client from the Download Center (helper bundled), then click "One-click setup" again.',
  'Windows：一键接入自动导入；iOS：在 OpenVPN Connect 中打开自动导入；Linux / macOS / Android：下载 .ovpn 后手动导入（Linux 见下载中心安装脚本，macOS 用 Tunnelblick，Android 用模方安全 APK）。':
    'Windows: one-click setup imports automatically. iOS: "Open in OpenVPN Connect" imports automatically. Linux / macOS / Android: download the .ovpn and import manually (Linux: install script in Download Center; macOS: Tunnelblick; Android: Modsafe APK).',
  // ── #131 iOS 深链导入（未安装探测：深链 2s 内页面未切后台=未安装）──
  '在 OpenVPN Connect 中打开': 'Open in OpenVPN Connect',
  '未检测到 OpenVPN Connect。请先从 App Store 安装，安装后回到本页再点一次「在 OpenVPN Connect 中打开」；或用下方「下载 .ovpn」在文件分享中选择 OpenVPN Connect 导入。':
    'OpenVPN Connect not detected. Install it from the App Store, come back and tap "Open in OpenVPN Connect" again; or use "Download .ovpn" below and choose OpenVPN Connect in the share sheet.',
  '未检测到 OpenVPN Connect。请先从 App Store 安装，安装后回到门户再点「一键连接」；或到「设备与配置」页下载 .ovpn 手动导入。':
    'OpenVPN Connect not detected. Install it from the App Store, come back and tap "One-click connect" again; or download the .ovpn from "Devices & profiles" and import manually.',
'绑定双因素认证': 'Set up two-factor authentication',
  '系统已强制双因素认证：请使用验证器 App 扫描或手动录入下方密钥，输入 6 位动态码完成绑定后重新登录。':
    'Two-factor auth is enforced system-wide. Scan or manually enter the key below in your authenticator app, type the 6-digit code to finish binding, then sign in again.',
  '获取绑定密钥': 'Get binding secret',
  '6 位动态验证码': '6-digit code',
  '验证并完成绑定': 'Verify & finish binding',
  '暂不绑定，退出登录': 'Not now — sign out',
  '请先完成双因素绑定': 'Please complete two-factor binding first',
  '客户端组件与各平台客户端下载': 'Helper component and clients for all platforms',
  '模方安全 客户端（Android）': 'Modsafe client (Android)',
  '基于成熟开源内核重构的品牌版（名称与图标为模方安全，支持国密 SM4/SM3）。安装后回到本页点「一键连接」，或在「设备」页下载 .ovpn 导入。':
    'Rebranded build of the open-source kernel (Modsafe name & icon, GM SM4/SM3 supported). Install, then click "Connect" here or import a .ovpn from the Devices page.',
  'Linux 客户端（信创 · 通用）': 'Linux client (XinChuang · universal)',
  '适配统信 UOS / 银河麒麟 / openEuler / CentOS / Ubuntu / Debian。脚本自动识别包管理器安装开源内核程序并配置 systemd 服务；配置从门户「设备」页下载。':
    'Works on UnionTech UOS / Kylin / openEuler / CentOS / Ubuntu / Debian. The script detects your package manager, installs the open-source kernel program and sets up systemd; download the profile from the Devices page.',
  '下载安装脚本': 'Download install script',
  'macOS 客户端（Tunnelblick）': 'macOS client (Tunnelblick)',
  '开源 macOS 客户端 Tunnelblick 9.0.1 官方构建（Intel/Apple Silicon 通用）。安装后拖入 .ovpn 配置即可；配置从门户「设备」页下载。':
    'Official build of the open-source Tunnelblick 9.0.1 (universal Intel/Apple Silicon). Drag the .ovpn profile in after install; download it from the Devices page.',
  '下载 DMG': 'Download DMG',
  '模方安全 客户端（Windows · 推荐）': 'Modsafe client (Windows · recommended)',
  '下载 APK': 'Download APK',
  '下载组件': 'Download helper',
  // ── 第二轮补齐（登录/设备/统计/连接明细）──
  '账号登录': 'Account sign-in',
  '返回扫码登录': 'Back to QR sign-in',
  '登录中…': 'Signing in…',
  '登录成功': 'Signed in',
  '请输入用户名': 'Enter username',
  '请输入密码': 'Enter password',
  '管理员账号': 'Administrator account',
  '初始账号见安装摘要，首次登录强制修改密码':
    'Initial credentials are in the installation summary. Password change is forced on first sign-in.',
  '已连接': 'Connected',
  '来自': 'from',
  '最近连接': 'Recent connections',
  '30 天上传': 'Upload (30d)',
  '30 天下载': 'Download (30d)',
  '还没有设备。': 'No devices yet.',
  '下载一份配置，导入客户端后即可连接。': 'Download a profile and import it into a client to connect.',
  '删除设备「{name}」？\n该设备的连接会立即断开，配置文件作废，需要重新下载。':
    'Delete device "{name}"?\nIts connection will be cut immediately and the profile invalidated — a re-download is required.',
  '共 {used}/{quota} 台可用额度，换电脑前先删旧设备':
    '{used}/{quota} device slots used. Remove an old device before switching computers.',
  '下载 .ovpn 配置文件（手动导入用）': 'Download .ovpn profile (for manual import)',
  '下载 .ovpn（手动导入用）': 'Download .ovpn (for manual import)',
  '一键接入（自动导入并连接）': 'One-click setup (import & connect)',
  '我已完成，进入门户': 'Done — go to portal',
  '一键连接需已安装模方安全客户端（安装包已内置连接组件）：':
    'One-click connect requires the Modsafe client (the installer bundles the helper):',
  '下载客户端安装包': 'Download the client installer',
  '。若本机已装开源内核客户端，单独安装组件即可：':
    '. If the open-source kernel client is already installed, just add the helper: ',
  '→ 同目录运行 install.bat（无需管理员）。':
    '→ Run install.bat from the same folder (no admin needed).',
  '连接后一直卡 WAIT：多为旧配置文件，重新生成一份；认证窗口没弹出：允许浏览器弹窗后重连。':
    'Stuck at WAIT after connecting: usually a stale profile — regenerate it. No auth window: allow browser pop-ups and reconnect.',
  '密码已修改。正在跳转登录…': 'Password changed. Redirecting to sign-in…',
  // 管理台补充
  '模方安全 管理台': 'Modsafe Admin',
  '至少 8 位；修改成功后需使用新密码重新登录':
    'At least 8 characters. You must sign in again with the new password after changing.',
  // 管理台补充
  '用户管理': 'Users',
  '管理操作日志': 'Admin Action Logs',
  // ── 第三轮补齐（用户实测缺词）──
  '一键连接': 'Connect',
  '使用统计': 'Usage',
  '下载中心': 'Downloads',
  '账号密码由你本人管理': 'You manage your own password',
  '已发起一键接入：请允许浏览器打开 modsafe 协议，之后全自动。若提示未安装组件，请先在本页底部下载组件并运行 install.bat。':
    'One-click setup initiated: allow the browser to open the modsafe protocol — everything else is automatic. If the helper is not installed, download it at the bottom of this page and run install.bat.',
  '{date}：上传 {up} / 下载 {down}': '{date}: upload {up} / download {down}',
  // ── 一键连接三态守卫（#120）──
  '当前已连接（本机检测 IP {ip}）。如需重连请先断开当前连接。': 'Already connected (local check IP {ip}). Disconnect before reconnecting.',
  '正在连接中，请勿重复发起。若长时间未上线，请断开后重试。': 'Connecting in progress — no need to start again. If it stays offline for long, disconnect and retry.',
  '正在检查连接状态…': 'Checking connection status…',
  '当前已连接（IP {ip}），无需重复连接。断开后可重新一键连接。': 'Already connected (IP {ip}) — no need to connect again. Disconnect first, then one-click reconnect.',
  '已发起连接：本机组件正在导入配置并连接，完成后自动上线。': 'Connection started: the local component is importing the profile and connecting. You will be online automatically.',
  '已发起连接：本机组件正在导入配置并连接。': 'Connection started: the local component is importing the profile and connecting.',
  '已发起连接。若点击后无反应，说明尚未安装客户端——请到「下载中心」下载安装 Windows 客户端（已内置连接组件）后重试。': 'Connection request sent. If nothing happened, the client is probably not installed — download and install the Windows client (connector included) from the Download Center, then try again.',
  '已发起连接。若点击后无反应，说明尚未安装组件——请到「下载中心」下载 modsafe-launcher.exe 并运行 install.bat 后重试。': 'Connection request sent. If nothing happened, the connector is probably not installed — download modsafe-launcher.exe from the Download Center and run install.bat, then try again.',
  // ── #130：安卓一键接入兜底提示 ──
  '已发起连接。若未跳转回应用，请先到「下载中心」安装安卓客户端「模方安全」，再回到门户点击「一键接入」。': 'Connection request sent. If the app did not open, install the Android app "模方安全" from the Download Center first, then tap One-click setup again.',
  // ── 安卓扫码导入二维码（P1）──
  '安卓：用相机或微信/钉钉/飞书扫此码，下载后打开即导入（App 内扫码可直连）': 'Android: scan with your camera or WeCom/DingTalk/Feishu, then open the downloaded file to import. In-app scanning connects directly.',
  // ── 用户侧双因素（2026-10-06）──
  '双因素认证': 'Two-factor authentication',
  '安全验证': 'Security verification',
  '企业策略已开启双因素认证：请绑定验证器后继续使用门户。': 'Your organization requires two-factor authentication. Set up an authenticator to continue using the portal.',
  '绑定后，登录门户需要在密码之外输入验证器 App 的 6 位动态码。': 'Once enabled, signing in to the portal requires a 6-digit code from your authenticator app in addition to your password.',
  '已启用双因素认证。输入当前动态码可关闭。': 'Two-factor authentication is on. Enter the current code to turn it off.',
  '用 Google Authenticator 等 App 扫此码（或手动输入密钥）': 'Scan with Google Authenticator or a compatible app (or enter the key manually)',
  '手动输入密钥': 'Manual key',
  '正在获取绑定密钥…': 'Fetching enrollment key…',
  '正在验证…': 'Verifying…',
  '验证并启用': 'Verify and enable',
  '关闭双因素': 'Turn off 2FA',
  '双因素绑定完成，下次门户登录需输入动态验证码': 'Two-factor authentication enabled. Next portal sign-in will ask for the dynamic code',
  '双因素已关闭': 'Two-factor authentication is off',
  '待绑定（企业策略要求）': 'Pending (required by policy)',
  '未启用': 'Off',
  '已启用': 'On',
};
