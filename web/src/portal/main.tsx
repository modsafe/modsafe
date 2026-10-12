/* 用户自助门户（§16）：移动优先、零 UI 库。
 * 设计：Apple 语言延续（parchment/白卡 18px/Action Blue/SF Pro 栈）+
 * 签名元素「通行证头卡」——深色证件卡承载身份与在线状态（呼吸灯），
 * 隐喻：打开门户 = 出示通行证。动效仅呼吸灯一处（respect reduced-motion）。 */
import { useEffect, useRef, useState } from 'react';
import QRCode from 'qrcode';
import { t, setLang, currentLang } from '../i18n';
import { createRoot } from 'react-dom/client';

const http = {
  post: async (path: string, body: unknown) => {
    const resp = await fetch(API + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(body),
    });
    const data = await resp.json();
    if (data.code !== 0) throw new Error(data.message || t('请求失败'));
    return data.data;
  },
};

const API = '/api/v1';
const LOCAL_STATUS = 'http://127.0.0.1:11443/status';

/** #130：安卓端门户深链导入——App 注册了 modsafe://setup（扫码导入/深链同一管线），
 * 安卓 UA 上「一键接入」直接发起深链，未装 App 时无跳转，提示到下载中心安装安卓客户端。 */
const IS_ANDROID = /Android/i.test(navigator.userAgent);

/** #131：iOS 分流——OpenVPN Connect v3 注册 openvpn:// scheme（import-profile 深链）。
 * iOS 端 scheme 未官方文档化，失败时静默无反应：所有 iOS 深链按钮必须配
 * 「下载 .ovpn」兜底与提示；下载 token 本身一次性+5 分钟有效，与深链时效天然匹配。 */
const IS_IOS = /iPad|iPhone|iPod/i.test(navigator.userAgent) ||
  (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);

/** #160：macOS 无 modsafe:// 处理器（Tunnelblick 手动导入流程）——一键连接改引导提示，
 * 配置下载自动切 .tblk 包（zip 内含 config.ovpn，双击即被 Tunnelblick 导入）。
 * iPadOS 13+ UA 伪装 Macintosh，须排除触屏设备。 */
const IS_MAC = /Mac/i.test(navigator.userAgent) && !IS_IOS;

function ovpnConnectLink(downloadUrl: string): string {
  return 'openvpn://import-profile/' + encodeURIComponent(location.origin + downloadUrl);
}

/** #131：拉起 OpenVPN Connect 并探测是否成功——iOS 网页无法直接查询 App 是否安装，
 * 用页面可见性启发式：深链成功时 Safari 退后台（visibilitychange/pagehide）；
 * 2 秒后页面仍在前台 = 未安装或未拉起 → 回调 onMiss 提示安装。 */
function tryOpenOvpnConnect(downloadUrl: string, onMiss: () => void): void {
  let missed = true;
  const left = () => { missed = false; };
  document.addEventListener('visibilitychange', left, { once: true });
  window.addEventListener('pagehide', left, { once: true });
  location.href = ovpnConnectLink(downloadUrl);
  setTimeout(() => {
    document.removeEventListener('visibilitychange', left);
    window.removeEventListener('pagehide', left);
    if (missed && !document.hidden) onMiss();
  }, 2000);
}

/** #115：探测本机插件（launcher 常驻监听）——返回 null = 未装/未运行；否则为实时连接状态。
 * connected=网卡已持有隧道地址；connecting=#120 近 120s 内发起过连接（握手/认证进行中）。
 * 仅访问固定常量 127.0.0.1 地址（launcher 只绑回环，CORS 白名单=企业门户来源）。 */
async function probeLocal(): Promise<{ connected: boolean; connecting: boolean; ip?: string } | null> {
  try {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 1200);
    const r = await fetch(LOCAL_STATUS, { signal: ctl.signal, credentials: 'omit' });
    clearTimeout(timer);
    if (!r.ok) return null;
    const d = await r.json();
    if (typeof d.connected !== 'boolean') return null;
    return { connected: d.connected, connecting: !!d.connecting, ip: d.ip || '' };
  } catch {
    return null;
  }
}

/** #120：一键连接统一守卫——三处按钮（首页/引导页/设备页）唯一入口，终结 #117/#119
 * 多处同形拼接各自为政的 bug 类。三态判定（优先级）：
 *   connected（本机探测，零延迟）→ 拦截「已连接」；
 *   connecting（#120 状态文件，零延迟）→ 拦截「连接中」——堵住握手/认证窗口内的重复发起；
 *   本机确认未连接 → 直接放行，不查服务端（台账滞后 ≤40s，实时重连的关键）；
 *   探测不可用（未装/监听未起）→ 服务端台账兜底；核实失败放行不硬阻断（#116 原则）。
 * 返回 'go-local' | 'go-fallback' | 'blocked'（blocked 时提示已由本函数给出）。 */
async function oneClickGuard(setHint: (s: string) => void): Promise<'go-local' | 'go-fallback' | 'blocked'> {
  const local = await probeLocal();
  if (local) {
    if (local.connected) {
      setHint(t('当前已连接（本机检测 IP {ip}）。如需重连请先断开当前连接。', { ip: local.ip || '-' }));
      return 'blocked';
    }
    if (local.connecting) {
      setHint(t('正在连接中，请勿重复发起。若长时间未上线，请断开后重试。'));
      return 'blocked';
    }
    return 'go-local';
  }
  setHint(t('正在检查连接状态…'));
  try {
    const fresh = await api<Me>('/self/me');
    if (fresh.online) {
      setHint(t('当前已连接（IP {ip}），无需重复连接。断开后可重新一键连接。', { ip: fresh.virtual_ip || '-' }));
      return 'blocked';
    }
    return 'go-fallback';
  } catch {
    return 'go-fallback';
  }
}

/** P1：安卓扫码导入二维码卡——内容=一次性下载链接+设备名+用户（App 扫码直导入；相机扫=浏览器下载兜底） */
function QrCard({ url, title }: { url: string; title: string }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    if (ref.current) QRCode.toCanvas(ref.current, url, { width: 168, margin: 1 }).catch(() => {});
  }, [url]);
  return (
    <div style={{ textAlign: 'center', marginTop: 14 }}>
      <canvas ref={ref} />
      <p className="sub" style={{ fontSize: 12, marginTop: 6 }}>{title}</p>
    </div>
  );
}

/* ── 请求封装 ── */
async function api<T = unknown>(path: string, init?: RequestInit): Promise<T> {
  // 同源路由门禁：门户请求目标恒为 /api/v1/self/*（fetch 目标恒同源相对路径，
  // 任何非 /self/ 路由一律拒绝——入口处收口，杜绝目标 URL 被构造）
  if (!/^\/self\/[A-Za-z0-9/._-]*$/.test(path)) throw new Error('bad api path');
  // 显式透传 method/body（不做 RequestInit 整体展开，请求形态固定可枚举）
  const resp = await fetch(API + path, {
    method: init?.method,
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: init?.body,
  });
  if (resp.status === 401) {
    window.location.href = API + '/self/login';
    throw new Error('unauthorized');
  }
  const body = await resp.json();
  if (body.code !== 0) throw new Error(body.message || t('请求失败'));
  return body.data as T;
}

// B 方案：网页一键连接的一次性 ticket（connect_grant）拼进深链/二维码。
// 老控制面无此字段时返回空串=行为与从前一致。
function grantQ(g?: string): string {
  return g ? '&g=' + encodeURIComponent(g) : '';
}

async function downloadOvpn(url: string, setToken?: (v: string) => void): Promise<void> {
  // 固定端点 + 请求体传参：从服务端下发的路径中取出一次性 token 尾段，
  // 不直接 fetch 服务端下发的 URL（客户端只 fetch 固定路由）
  const tail = url.split('?')[0].split('/').pop() || '';
  const fmt = url.includes('fmt=tunnelblick') ? 'tunnelblick' : '';
  const resp = await fetch(API + '/client-config/download', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ token: tail, fmt }),
  });
  const ct = resp.headers.get('Content-Type') || '';
  if (!resp.ok || ct.includes('application/json')) {
    let msg = t('下载链接已失效，请重新生成');
    try {
      const b = await resp.json();
      if (b.message) msg = b.message;
    } catch {
      /* ignore */
    }
    alert(msg);
    if (setToken) setToken('');
    return;
  }
  const blob = await resp.blob();
  const cd = resp.headers.get('Content-Disposition') || '';
  // RFC 5987 filename* 优先（还原中文原名），回退 ASCII filename，最后 config.ovpn
  const mStar = cd.match(/filename\*=(?:UTF-8|utf-8)''([^;]+)/);
  const m = cd.match(/filename="?([^";]+)"?/);
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = mStar ? decodeURIComponent(mStar[1]) : (m ? m[1] : 'config.ovpn');
  a.click();
  URL.revokeObjectURL(a.href);
}

function fmtBytes(b: number): string {
  if (!b) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(b) / Math.log(1024)), u.length - 1);
  return `${(b / 1024 ** i).toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
}

interface Me {
  user_id: number;
  username: string;
  display_name: string;
  source: string;
  online: boolean;
  virtual_ip: string;
  device_quota: number;
  device_used: number;
  onboarded: boolean;
  is_local: boolean;
  latest_profile: string;
  totp_enabled: boolean;
  totp_required: boolean;
}
interface Device {
  id: number;
  cert_cn: string;
  platform: string;
  fingerprint: string;
  created_at: string;
  status: string;
}
interface DayUsage {
  date: string;
  in: number;
  out: number;
}
interface SessionRow {
  virtual_ip: string;
  trusted_ip: string;
  node: string;
  connected_at: string;
  last_seen: string;
  bytes_in: number;
  bytes_out: number;
  online: boolean;
}

const SOURCE_LABEL = (): Record<string, string> => ({
  local: t('本地账号'),
  dingtalk: t('钉钉'),
  wecom: t('企业微信'),
  feishu: t('飞书'),
  openldap: 'OpenLDAP',
  'ldap-ad': t('AD 域'),
});

/* ── 设计 token（CSS）── */
const css = `
*{box-sizing:border-box;-webkit-font-smoothing:antialiased}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC","Helvetica Neue","Microsoft YaHei",sans-serif;background:#f5f5f7;color:#1d1d1f;min-height:100vh}
#root{max-width:640px;margin:0 auto;min-height:100vh;display:flex;flex-direction:column}

.top{display:flex;align-items:center;gap:10px;padding:16px 20px 8px}
.logo{width:42px;height:42px;border-radius:12px;background:#EFF6FF;color:#fff;display:flex;align-items:center;justify-content:center;font-weight:600;font-size:16px;flex:none}
.brand{font-size:16px;font-weight:600;letter-spacing:-.3px;line-height:1.15}
.brand small{display:block;font-size:11px;color:#7a7a7a;font-weight:400;letter-spacing:.3px}
.logout{margin-left:auto;color:#1D4ED8;font-size:15px;background:none;border:none;cursor:pointer;padding:8px}

/* 签名元素：通行证头卡（#91 品牌化：黑→品牌深蓝 Deep Navy） */
.pass{position:relative;background:#12307A;color:#fff;border-radius:22px;margin:10px 16px;padding:22px 20px 18px;overflow:hidden}
.pass .no{position:absolute;top:14px;right:16px;font-size:10px;letter-spacing:.6px;color:rgba(255,255,255,.38);font-variant-numeric:tabular-nums}
.pass .name{font-size:28px;font-weight:600;letter-spacing:-.4px;line-height:1.1;margin:2px 0 2px}
.pass .sub{font-size:13px;color:rgba(255,255,255,.6)}
.pass .status{display:flex;align-items:center;gap:8px;margin-top:14px;font-size:15px}
.dot{width:10px;height:10px;border-radius:50%;flex:none}
.dot.on{background:#34c759;animation:breath 2.4s ease-in-out infinite}
.dot.off{background:rgba(255,255,255,.28)}
@keyframes breath{0%,100%{box-shadow:0 0 0 0 rgba(52,199,89,.45)}55%{box-shadow:0 0 0 7px rgba(52,199,89,0)}}
@media (prefers-reduced-motion: reduce){.dot.on{animation:none}}
.pass .meta{display:flex;gap:22px;margin-top:16px;padding-top:14px;border-top:1px solid rgba(255,255,255,.14)}
.pass .meta b{display:block;font-size:17px;font-weight:600;font-variant-numeric:tabular-nums}
.pass .meta span{display:block;font-size:11px;color:rgba(255,255,255,.55);margin-top:1px}
.pass .meta .bar{width:74px;height:4px;border-radius:2px;background:rgba(255,255,255,.18);margin-top:6px;overflow:hidden}
.pass .meta .bar i{display:block;height:100%;background:#34c759;border-radius:2px}

.card{background:#fff;border:1px solid #e0e0e0;border-radius:18px;padding:18px 18px;margin:12px 16px}
.h{font-size:21px;font-weight:600;letter-spacing:-.37px;margin:16px 20px 2px}
.sub{font-size:13px;color:#7a7a7a;margin:0 20px;line-height:1.45}

.btn{display:block;width:100%;padding:13px 22px;border:none;border-radius:9999px;background:#1D4ED8;color:#fff;font-size:17px;font-family:inherit;text-align:center;cursor:pointer;text-decoration:none;transition:transform .1s ease}
.btn:active{transform:scale(.95)}
.btn:focus-visible{outline:2px solid #3B82F6;outline-offset:2px}
.btn.ghost{background:#fff;color:#1D4ED8;border:1px solid #1D4ED8}
.btn.red{background:#d70015;padding:8px 16px;width:auto;font-size:14px}
.btn[disabled]{opacity:.4;pointer-events:none}
.acts{display:flex;gap:10px;margin:12px 16px}
.acts .btn{flex:1}

.field label{display:block;font-size:14px;color:#6e6e73;margin:14px 0 6px}
.field input{width:100%;height:44px;padding:0 16px;border:1px solid #d2d2d7;border-radius:9999px;font-size:17px;font-family:inherit;background:#fff;color:#1d1d1f}
.field input:focus{border-color:#1D4ED8;outline:none}
.err{color:#d70015;font-size:14px;margin:10px 0 0;line-height:1.4}

.row{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:12px 0;border-bottom:1px solid #f0f0f0;font-size:15px}
.row:last-child{border-bottom:none}
.row .k{color:#6e6e73}
.pill{display:inline-block;padding:2px 10px;border-radius:9999px;font-size:12px;flex:none}
.pill.ok{background:#e8f5e9;color:#1e7e34}
.pill.off{background:#f0f0f0;color:#7a7a7a}

/* 时间线（真实顺序的结构表达） */
.tl{position:relative;padding-left:30px}
.tl:before{content:"";position:absolute;left:9px;top:8px;bottom:14px;width:2px;background:#e0e0e0;border-radius:1px}
.tl .step{position:relative;padding:0 0 20px}
.tl .step:last-child{padding-bottom:2px}
.tl .step:before{content:"";position:absolute;left:-27px;top:5px;width:12px;height:12px;border-radius:50%;background:#1D4ED8;border:3px solid #fff;box-shadow:0 0 0 1px #d2d2d7}
.tl h4{margin:0 0 3px;font-size:17px;font-weight:600;letter-spacing:-.2px}
.tl p{margin:0;font-size:14px;color:#6e6e73;line-height:1.5}

/* 底部 Tab（毛玻璃） */
.tabs{position:sticky;bottom:0;display:flex;background:rgba(245,245,247,.9);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border-top:1px solid #e0e0e0;margin-top:auto;padding-bottom:env(safe-area-inset-bottom)}
.tabs button{flex:1;text-align:center;padding:9px 0 7px;font-size:11px;color:#7a7a7a;background:none;border:none;cursor:pointer;font-family:inherit}
.tabs button.on{color:#1D4ED8;font-weight:600}
.tabs svg{display:block;margin:0 auto 3px;width:23px;height:23px}

/* 统计柱 */
.chart{display:flex;align-items:flex-end;gap:3px;height:120px;margin:14px 0 4px}
.chart .colwrap{flex:1;display:flex;flex-direction:column;justify-content:flex-end;gap:1px;height:100%;min-width:4px}
.chart .col{width:100%;background:#1D4ED8;border-radius:2px 2px 0 0;min-height:2px}
.chart .col.in{background:#34c759}
.bignum{display:flex;gap:26px;margin:4px 0 2px}
.bignum b{display:block;font-size:26px;font-weight:600;letter-spacing:-.4px;font-variant-numeric:tabular-nums}
.bignum span{display:block;font-size:12px;color:#7a7a7a;margin-top:2px}

.empty{padding:26px 8px;text-align:center;color:#6e6e73;font-size:14px;line-height:1.6}
.login-wrap{max-width:340px;margin:12vh auto 0;width:88%;text-align:center}
`;

/* ── 本地登录 ── */
function LoginLocal({ onDone }: { onDone: () => void }) {
  const [u, setU] = useState('');
  const [p, setP] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const go = async () => {
    setBusy(true);
    setErr('');
    try {
      await api('/self/login-local', { method: 'POST', body: JSON.stringify({ username: u, password: p }) });
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="login-wrap">
      <div className="logo" style={{ margin: '0 auto 14px', width: 56, height: 56, borderRadius: 14, background: 'transparent' }}>
        <svg viewBox="0 0 120 120" width="100%" height="100%" role="img" aria-label="Modsafe">
          <polygon points="20,34 86,34 100,20 34,20" fill="#3B82F6" />
          <polygon points="86,34 100,20 100,86 86,100" fill="#12307A" />
          <rect x="20" y="34" width="66" height="66" fill="#1D4ED8" />
          <path d="M37 44 H69 C71.21 44 73 45.79 73 48 V67 C73 78 66 84 53 89 C40 84 33 78 33 67 V48 C33 45.79 34.79 44 37 44 Z" fill="#FFFFFF" />
        </svg>
      </div>
      <h2 style={{ fontSize: 24, fontWeight: 600, letterSpacing: '-0.4px', margin: 0 }}>{t('账号登录')}</h2>
      <p style={{ color: '#7a7a7a', fontSize: 14, margin: '6px 0 18px' }}>{t('企业扫码用户请从扫码入口进入')}</p>
      <div className="card" style={{ textAlign: 'left' }}>
        <div className="field">
          <label>{t('账号')}</label>
          <input value={u} autoComplete="username" onChange={(e) => setU(e.target.value)} />
        </div>
        <div className="field">
          <label>{t('密码')}</label>
          <input type="password" value={p} autoComplete="current-password" onChange={(e) => setP(e.target.value)} />
        </div>
        {err && <p className="err">{err}</p>}
        <button className="btn" style={{ marginTop: 18 }} disabled={busy} onClick={go}>
          {busy ? t('登录中…') : t('登录')}
        </button>
        <button
          style={{ display: 'block', textAlign: 'center', margin: '14px auto 0', color: '#1D4ED8', fontSize: 15, background: 'none', border: 'none', cursor: 'pointer' }}
          onClick={() => (window.location.href = API + '/self/login')}
        >
          {t('返回扫码登录')}
        </button>
        <button
          style={{ display: 'block', textAlign: 'center', margin: '6px auto 0', color: '#7a7a7a', fontSize: 13, background: 'none', border: 'none', cursor: 'pointer' }}
          onClick={() => setLang(currentLang() === 'zh' ? 'en' : 'zh')}
        >
          {currentLang() === 'zh' ? 'English' : '中文'}
        </button>
      </div>
    </div>
  );
}

/* ── 通行证头卡（签名元素）── */
function PassCard({ me, usage }: { me: Me; usage: { total_in: number; total_out: number } | null }) {
  const pct = Math.min(100, (me.device_used / Math.max(1, me.device_quota)) * 100);
  return (
    <div className="pass">
      <div className="no">PASS · {me.source.toUpperCase()}</div>
      <div className="name">{me.display_name || me.username}</div>
      <div className="sub">@{me.username} · {SOURCE_LABEL()[me.source] || me.source}</div>
      <div className="status">
        <span className={`dot ${me.online ? 'on' : 'off'}`} />
        {me.online ? <span>已连接 · {me.virtual_ip}</span> : <span style={{ color: 'rgba(255,255,255,.75)' }}>{t('未连接')}</span>}
      </div>
      <div className="meta">
        <div>
          <b>
            {me.device_used}
            <span style={{ fontWeight: 400, color: 'rgba(255,255,255,.55)' }}>/{me.device_quota}</span>
          </b>
          <span>{t('我的设备')}</span>
          <div className="bar">
            <i style={{ width: `${pct}%` }} />
          </div>
        </div>
        <div>
          <b>{fmtBytes((usage?.total_in ?? 0) + (usage?.total_out ?? 0))}</b>
          <span>{t('近 30 天流量')}</span>
        </div>
      </div>
    </div>
  );
}

/* ── 首次接入引导（时间线）── */
function Onboarding({ me, onDone }: { me: Me; onDone: () => void }) {
  const [token, setToken] = useState('');
  const [grant, setGrant] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [setupHint, setSetupHint] = useState('');
  const gen = async () => {
    setBusy(true);
    setErr('');
    try {
      const d = await api<{ download_url: string; connect_grant?: string }>('/self/devices/client-config', {
        method: 'POST',
        body: JSON.stringify({ device_name: 'my-device', platform: navigator.platform || '' }),
      });
      setToken(d.download_url);
      setGrant(d.connect_grant || '');
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <PassCard me={me} usage={null} />
      <h2 className="h">{t('接入内部网络')}</h2>
      <p className="sub">{t('三步完成，全程不需要管理员')}</p>
      <div className="card">
        <div className="tl">
          <div className="step">
            <h4>{t('下载我的接入配置')}</h4>
            <p>{t('生成一份含个人证书的 .ovpn 文件。链接 5 分钟内有效，只能下载一次，请下载后妥善保存。')}</p>
          </div>
          <div className="step">
            <h4>{t('导入客户端')}</h4>
            <p>{t('Windows：一键接入自动导入；iOS：在 OpenVPN Connect 中打开自动导入；macOS：下载 .ovpn 后双击导入 Tunnelblick（连接时用户名填本人姓名，密码随意）；Linux / Android：下载 .ovpn 后手动导入（Linux 见下载中心安装脚本，Android 用模方安全 APK）。')}</p>
          </div>
          <div className="step">
            <h4>{t('完成连接')}</h4>
            <p>{t('一键接入后全自动；手动导入的，连接时浏览器会弹出企业认证，扫码通过即上线（之后当天免扫码）。')}</p>
          </div>
        </div>
        {err && <p className="err">{err}</p>}
        {token ? (
          <>
            <button
              className="btn ghost"
              style={{ marginTop: 16 }}
              onClick={() => downloadOvpn(token + (IS_MAC ? '?fmt=tunnelblick' : ''), setToken)}
            >
              {IS_MAC ? t('下载 .ovpn（双击导入 Tunnelblick）') : t('下载 .ovpn 配置文件（手动导入用）')}
            </button>
            {IS_IOS ? (
              <button
                className="btn"
                style={{ marginTop: 16 }}
                onClick={() => {
                  tryOpenOvpnConnect(token, () =>
                    setSetupHint(t('未检测到 OpenVPN Connect。请先从 App Store 安装，安装后回到本页再点一次「在 OpenVPN Connect 中打开」；或用下方「下载 .ovpn」在文件分享中选择 OpenVPN Connect 导入。')));
                }}
              >
                {t('在 OpenVPN Connect 中打开')}
              </button>
            ) : (
            <button
              className="btn"
              style={{ marginTop: 12 }}
              onClick={async () => {
                // #120：三态守卫统一入口（connecting/connected 拦截、未连接放行、探测不可用走服务端）
                if (IS_MAC) {
                  setSetupHint(t('macOS：请点上方「下载 .ovpn」保存后双击，Tunnelblick 会自动导入。'));
                  return;
                }
                const verdict = await oneClickGuard(setSetupHint);
                if (verdict === 'blocked') return;
                const name = encodeURIComponent('u' + (me.user_id ?? 0) + '-my-device');
                const uname = encodeURIComponent(me.display_name || me.username);
                location.href = 'modsafe://setup?token=' + token.split('/').pop() + '&base=' + encodeURIComponent(location.origin) + '&name=' + name + '&u=' + uname + grantQ(grant);
                setSetupHint(verdict === 'go-local'
                  ? t('已发起连接：本机组件正在导入配置并连接。')
                  : IS_ANDROID
                    ? t('已发起连接。若未跳转回应用，请先到「下载中心」安装安卓客户端「模方安全」，再回到门户点击「一键接入」。')
                    : t('已发起连接。若点击后无反应，说明尚未安装组件——请到「下载中心」下载 modsafe-launcher.exe 并运行 install.bat 后重试。'));
              }}
            >
              {t('一键接入（自动导入并连接）')}
            </button>
            )}
            <button className="btn ghost" style={{ marginTop: 12 }} onClick={onDone}>
              {t('我已完成，进入门户')}
            </button>
            <QrCard
              url={location.origin + '/api/v1/client-config/' + token.split('/').pop() + '?name=' + encodeURIComponent('u' + (me.user_id ?? 0) + '-my-device') + '&u=' + encodeURIComponent(me.display_name || me.username) + grantQ(grant)}
              title={t('安卓：用相机或微信/钉钉/飞书扫此码，下载后打开即导入（App 内扫码可直连）')}
            />
          </>
        ) : (
          <button className="btn" style={{ marginTop: 16 }} disabled={busy} onClick={gen}>
            {busy ? t('正在生成…') : t('生成我的配置文件')}
          </button>
        )}
      </div>
      {setupHint && (
        <p className="sub" style={{ marginTop: 4, color: '#1D4ED8' }}>
          {setupHint}
        </p>
      )}
      <p className="sub" style={{ marginTop: 4 }}>
        {t('一键连接需已安装模方安全客户端（安装包已内置连接组件）：')}
        <a href="/launcher/Modsafe-Setup.exe" style={{ color: '#1D4ED8' }}>
          {t('下载客户端安装包')}
        </a>{' '}
        {t('。若本机已装开源内核客户端，单独安装组件即可：')}
        <a href="/launcher/modsafe-launcher.exe" style={{ color: '#1D4ED8' }}>
          {t('下载组件')}
        </a>{' '}
        {t('→ 同目录运行 install.bat（无需管理员）。')}
      </p>
      <p className="sub">{t('连接后一直卡 WAIT：多为旧配置文件，重新生成一份；认证窗口没弹出：允许浏览器弹窗后重连。')}</p>
    </>
  );
}

/* ── 主页 ── */
function Home({ me, usage, go }: { me: Me; usage: { total_in: number; total_out: number } | null; go: (v: string) => void }) {
  const [hint, setHint] = useState('');
  return (
    <>
      <PassCard me={me} usage={usage} />
      {hint && (
        <p className="sub" style={{ margin: '0 20px 6px', color: '#1D4ED8' }}>
          {hint}
        </p>
      )}
      <div className="acts">
        <button
          className="btn"
          onClick={async () => {
            // #160：macOS 无 modsafe:// 处理器——引导走 .ovpn 双击导入 Tunnelblick
            if (IS_MAC) {
              setHint(t('macOS：请在「设备与配置」页下载 .ovpn，保存后双击即可导入 Tunnelblick。'));
              go('devices');
              return;
            }
            // #120：三态守卫统一入口——connected/connecting（本机零延迟）拦截；确认未连接直接放行
            //（不查服务端——台账滞后 ≤40s）；探测不可用降级服务端核实（核实失败放行，#116 原则）。
            const verdict = await oneClickGuard(setHint);
            if (verdict === 'blocked') return;
            setHint(t('正在准备一键连接…'));
            try {
              const devName = 'u' + me.user_id + '-auto';
              if (me.device_used >= me.device_quota) {
                alert(t('设备额度已满，请先到「设备」页删除旧设备。'));
                go('devices');
                return;
              }
              const d = await http.post('/self/devices/client-config', {
                device_name: devName, platform: navigator.platform || '',
              });
              // #131：iOS 不走 modsafe://（那是安卓 App/Windows launcher 的管线），
              // 改拉起 OpenVPN Connect 的 import-profile 深链（未安装则 2s 后提示）
              if (IS_IOS) {
                tryOpenOvpnConnect(d.download_url, () =>
                  setHint(t('未检测到 OpenVPN Connect。请先从 App Store 安装，安装后回到门户再点「一键连接」；或到「设备与配置」页下载 .ovpn 手动导入。')));
                return;
              }
              const uname = encodeURIComponent(me.display_name || me.username);
              location.href = 'modsafe://setup?token=' + d.download_url.split('/').pop() + '&base=' + encodeURIComponent(location.origin) + '&name=' + encodeURIComponent(devName) + '&u=' + uname + grantQ(d.connect_grant);
              setHint(verdict === 'go-local'
                ? t('已发起连接：本机组件正在导入配置并连接，完成后自动上线。')
                : IS_ANDROID
                  ? t('已发起连接。若未跳转回应用，请先到「下载中心」安装安卓客户端「模方安全」，再回到门户点击「一键接入」。')
                  : t('已发起连接。若点击后无反应，说明尚未安装客户端——请到「下载中心」下载安装 Windows 客户端（已内置连接组件）后重试。'));
            } catch (e) {
              setHint('');
              alert((e as Error).message);
            }
          }}
        >
          {t('一键连接')}
        </button>
        <button className="btn ghost" onClick={() => go('devices')}>
          {t('设备与配置')}
        </button>
      </div>
      <div className="acts">
        <button className="btn ghost" onClick={() => go('usage')}>
          {t('使用统计')}
        </button>
      </div>
      {me.is_local && (
        <div className="card" style={{ padding: 14, display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ flex: 1, fontSize: 14, color: '#6e6e73' }}>{t('账号密码由你本人管理')}</div>
          <button className="btn ghost" style={{ width: 'auto', padding: '8px 18px', fontSize: 14 }} onClick={() => go('password')}>
            {t('修改密码')}
          </button>
        </div>
      )}
    </>
  );
}

/* ── 我的设备 ── */
function Devices({ refreshMe, me }: { refreshMe: () => void; me: Me | null }) {
  const [data, setData] = useState<{ list: Device[]; quota: number; used: number } | null>(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [token, setToken] = useState('');
  const [grant, setGrant] = useState('');
  const [devHint, setDevHint] = useState('');
  const load = () =>
    api<{ list: Device[]; quota: number; used: number }>('/self/devices')
      .then(setData)
      .catch((e) => setErr((e as Error).message));
  useEffect(() => {
    load();
  }, []);
  const gen = async () => {
    setBusy(true);
    setErr('');
    try {
      const d = await api<{ download_url: string; connect_grant?: string }>('/self/devices/client-config', {
        method: 'POST',
        body: JSON.stringify({ device_name: 'my-device', platform: navigator.platform || '' }),
      });
      setToken(d.download_url);
      setGrant(d.connect_grant || '');
      load();
      refreshMe();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const revoke = async (d: Device) => {
    if (!window.confirm(t('删除设备「{name}」？\n该设备的连接会立即断开，配置文件作废，需要重新下载。', { name: d.platform || t('设备') }))) return;
    try {
      await api('/self/devices/delete', { method: 'POST', body: JSON.stringify({ id: d.id }) });
      load();
      refreshMe();
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  const full = data ? data.used >= data.quota : false;
  const active = (data?.list ?? []).filter((d) => d.status === 'active');
  return (
    <>
      <h2 className="h">{t('我的设备')}</h2>
      <p className="sub">{data ? t('共 {used}/{quota} 台可用额度，换电脑前先删旧设备', { used: data.used, quota: data.quota }) : ''}</p>
      <div className="card">
        {active.map((d) => (
          <div className="row" key={d.id}>
            <div style={{ minWidth: 0 }}>
              <div style={{ fontWeight: 600 }}>{d.platform || t('我的设备')}</div>
              <div style={{ fontSize: 12, color: '#7a7a7a', marginTop: 2 }}>
                {d.created_at} · {d.fingerprint}
              </div>
            </div>
            <button className="btn red" onClick={() => revoke(d)}>
              {t('删除')}
            </button>
          </div>
        ))}
        {data && active.length === 0 && (
          <div className="empty">
            {t('还没有设备。')}
            <br />
            {t('下载一份配置，导入客户端后即可连接。')}
          </div>
        )}
        {err && <p className="err">{err}</p>}
        {devHint && <p className="sub" style={{ color: '#1D4ED8' }}>{devHint}</p>}
        {token ? (
        <>
          {IS_IOS ? (
            <button
              className="btn"
              style={{ marginTop: 14 }}
              onClick={() => {
                tryOpenOvpnConnect(token, () =>
                  setDevHint(t('未检测到 OpenVPN Connect。请先从 App Store 安装，安装后回到本页再点一次「在 OpenVPN Connect 中打开」；或用下方「下载 .ovpn」在文件分享中选择 OpenVPN Connect 导入。')));
              }}
            >
              {t('在 OpenVPN Connect 中打开')}
            </button>
          ) : (
          <button
            className="btn"
            style={{ marginTop: 14 }}
            onClick={async () => {
              // #160：macOS 无 modsafe:// 处理器——引导走 .ovpn 双击导入 Tunnelblick
              if (IS_MAC) {
                setDevHint(t('macOS：请点下方「下载 .ovpn」保存后双击，Tunnelblick 会自动导入。'));
                return;
              }
              // #120：三态守卫统一入口（探测优先实时判定；探测不可用降级服务端台账核实）
              const verdict = await oneClickGuard(setDevHint);
              if (verdict === 'blocked') return;
              const name = encodeURIComponent('u' + (me?.user_id ?? 0) + '-my-device');
              const uname = encodeURIComponent(me?.display_name || me?.username || '');
              location.href = 'modsafe://setup?token=' + token.split('/').pop() + '&base=' + encodeURIComponent(location.origin) + '&name=' + name + '&u=' + uname + grantQ(grant);
              setDevHint(verdict === 'go-local'
                ? t('已发起连接：本机组件正在导入配置并连接。')
                : IS_ANDROID
                  ? t('已发起连接。若未跳转回应用，请先到「下载中心」安装安卓客户端「模方安全」，再回到门户点击「一键接入」。')
                  : t('已发起连接。若点击后无反应，说明尚未安装组件——请到「下载中心」下载 modsafe-launcher.exe 并运行 install.bat 后重试。'));
            }}
          >
            {t('一键接入（自动导入并连接）')}
          </button>
          )}
          <button
            className="btn ghost"
            style={{ marginTop: 12 }}
            onClick={() => downloadOvpn(token + (IS_MAC ? '?fmt=tunnelblick' : ''), setToken)}
          >
            {IS_MAC ? t('下载 .ovpn（双击导入 Tunnelblick）') : t('下载 .ovpn（手动导入用）')}
          </button>
          <QrCard
            url={location.origin + '/api/v1/client-config/' + token.split('/').pop() + '?name=' + encodeURIComponent('u' + (me?.user_id ?? 0) + '-my-device') + '&u=' + encodeURIComponent(me?.display_name || me?.username || '') + grantQ(grant)}
            title={t('安卓：用相机或微信/钉钉/飞书扫此码，下载后打开即导入（App 内扫码可直连）')}
          />
        </>
      ) : (
          <button className="btn" style={{ marginTop: 14 }} disabled={busy || full} onClick={gen}>
            {full ? t('额度已满，先删除一台旧设备') : busy ? t('正在生成…') : t('添加新设备')}
          </button>
        )}
      </div>
    </>
  );
}

/* ── 使用统计 ── */
function Usage() {
  const [u, setU] = useState<{ days: DayUsage[]; total_in: number; total_out: number } | null>(null);
  const [rows, setRows] = useState<SessionRow[]>([]);
  useEffect(() => {
    api<{ days: DayUsage[]; total_in: number; total_out: number }>('/self/usage').then(setU).catch(() => {});
    api<{ list: SessionRow[] }>('/self/sessions?page=1&pageSize=20').then((d) => setRows(d.list)).catch(() => {});
  }, []);
  const max = Math.max(1, ...(u?.days ?? []).map((d) => d.in + d.out));
  return (
    <>
      <h2 className="h">{t('使用统计')}</h2>
      <p className="sub">{t('近 30 天 · 绿色为上传，蓝色为下载')}</p>
      <div className="card">
        <div className="bignum">
          <div>
            <b>{fmtBytes(u?.total_in ?? 0)}</b>
            <span>{t('30 天上传')}</span>
          </div>
          <div>
            <b>{fmtBytes(u?.total_out ?? 0)}</b>
            <span>{t('30 天下载')}</span>
          </div>
        </div>
        <div className="chart">
          {(u?.days ?? []).map((d) => (
            <div key={d.date} className="colwrap" title={t('{date}：上传 {up} / 下载 {down}', { date: d.date, up: fmtBytes(d.in), down: fmtBytes(d.out) })}>
              <div className="col" style={{ height: `${Math.max(2, (d.out / max) * 100)}%` }} />
              <div className="col in" style={{ height: `${Math.max(2, (d.in / max) * 100)}%` }} />
            </div>
          ))}
        </div>
        {(u?.days ?? []).length === 0 && <div className="empty">{t('还没有流量记录，连上后这里会出现你的使用情况。')}</div>}
      </div>
      <h2 className="h" style={{ fontSize: 17 }}>{t('最近连接')}</h2>
      <div className="card">
        {rows.map((s, i) => (
          <div className="row" key={i}>
            <div style={{ minWidth: 0 }}>
              <div>{s.virtual_ip}</div>
              <div style={{ fontSize: 12, color: '#7a7a7a', marginTop: 2 }}>
                {s.connected_at} · {t('来自')} {s.trusted_ip}
              </div>
            </div>
            <div style={{ textAlign: 'right', fontSize: 13, flex: 'none' }}>
              <div style={{ fontVariantNumeric: 'tabular-nums' }}>
                ↑{fmtBytes(s.bytes_in)} ↓{fmtBytes(s.bytes_out)}
              </div>
              <div style={{ marginTop: 4 }}>{s.online ? <span className="pill ok">{t('在线')}</span> : <span className="pill off">{t('已断开')}</span>}</div>
            </div>
          </div>
        ))}
        {rows.length === 0 && <div className="empty">{t('还没有连接记录。')}</div>}
      </div>
    </>
  );
}

/* ── 下载中心 ── */
function Downloads() {
  const items = [
    {
      title: t('模方安全 客户端（Windows · 推荐）'),
      desc: t('一体化安装包（内置成熟开源内核 2.7.7 DCO 数据加速、国密 SM4/SM3 加密、网页一键连接组件）。安装完成后会自动打开本门户，点「一键连接」即可使用——无需再装任何其他组件。'),
      links: [{ label: t('下载安装包'), url: '/launcher/Modsafe-Setup.exe' }],
    },
    {
      title: t('模方安全 客户端（Android）'),
      desc: t('基于成熟开源内核重构的品牌版（名称与图标为模方安全，支持国密 SM4/SM3）。安装后回到本页点「一键连接」，或在「设备」页下载 .ovpn 导入。'),
      links: [
        { label: t('下载 APK'), url: '/launcher/modsafe-android.apk' },
      ],
    },
    {
      title: t('Linux 客户端（信创 · 通用）'),
      desc: t('适配统信 UOS / 银河麒麟 / openEuler / CentOS / Ubuntu / Debian。脚本自动识别包管理器安装开源内核程序并配置 systemd 服务；配置从门户「设备」页下载。'),
      links: [
        { label: t('下载安装脚本'), url: '/launcher/modsafe-linux-install.sh' },
      ],
    },
    {
      title: t('macOS 客户端（Tunnelblick）'),
      desc: t('开源 macOS 客户端 Tunnelblick 9.0.1 官方构建（Intel/Apple Silicon 通用）。安装后拖入 .ovpn 配置即可；配置从门户「设备」页下载。'),
      links: [
        { label: t('下载 DMG'), url: '/launcher/modsafe-macos-tunnelblick.dmg' },
      ],
    },
    {
      title: 'OpenVPN Connect（iOS）',
      desc: t('iPhone/iPad 客户端，从 App Store 安装后在应用内导入 .ovpn 配置。'),
      links: [
        { label: 'App Store', url: 'https://apps.apple.com/app/openvpn-connect/id590379981' },
      ],
    },
  ];
  return (
    <>
      <h2 className="h">{t('下载中心')}</h2>
      <p className="sub">{t('客户端组件与各平台客户端下载')}</p>
      {items.map((item) => (
        <div className="card" key={item.title}>
          <div style={{ fontWeight: 600, fontSize: 17, marginBottom: 4 }}>{item.title}</div>
          <p style={{ fontSize: 14, color: '#6e6e73', margin: '0 0 10px', lineHeight: 1.5 }}>{item.desc}</p>
          {item.links.map((link) => (
            <a
              key={link.label}
              href={link.url}
              download
              style={{ display: 'inline-block', padding: '8px 16px', marginRight: 8, borderRadius: 9999, background: '#1D4ED8', color: '#fff', textDecoration: 'none', fontSize: 14 }}
            >
              {link.label}
            </a>
          ))}
        </div>
      ))}
    </>
  );
}

/* ── 双因素认证（绑定/关闭；企业策略强制态接管整个门户）── */
function Totp({ me, forced, onDone }: { me: Me; forced?: boolean; onDone: () => void }) {
  const [setup, setSetup] = useState<{ secret: string; otpauth_uri: string; enabled: boolean } | null>(null);
  const [code, setCode] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const load = () => {
    api<{ secret: string; otpauth_uri: string; enabled: boolean }>('/self/totp/setup')
      .then(setSetup)
      .catch((e) => setErr((e as Error).message));
  };
  useEffect(load, []);
  const submit = async () => {
    setBusy(true);
    setErr('');
    const enabling = !(me.totp_enabled || setup?.enabled);
    try {
      await api(`/self/totp/${enabling ? 'enable' : 'disable'}`, {
        method: 'POST',
        body: JSON.stringify({ code }),
      });
      if (enabling) {
        alert(t('双因素绑定完成，下次门户登录需输入动态验证码'));
      } else {
        alert(t('双因素已关闭'));
      }
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const enabling = !(me.totp_enabled || setup?.enabled);
  return (
    <>
      <h2 className="h">{t('双因素认证')}</h2>
      <p className="sub">
        {forced
          ? t('企业策略已开启双因素认证：请绑定验证器后继续使用门户。')
          : enabling
            ? t('绑定后，登录门户需要在密码之外输入验证器 App 的 6 位动态码。')
            : t('已启用双因素认证。输入当前动态码可关闭。')}
      </p>
      <div className="card">
        {enabling ? (
          setup ? (
            <>
              <QrCard url={setup.otpauth_uri} title={t('用 Google Authenticator 等 App 扫此码（或手动输入密钥）')} />
              <p className="sub" style={{ fontSize: 12, wordBreak: 'break-all', textAlign: 'center' }}>
                {t('手动输入密钥')}：{setup.secret}
              </p>
            </>
          ) : (
            <div className="empty">{t('正在获取绑定密钥…')}</div>
          )
        ) : null}
        <div className="field">
          <label>{t('6 位动态验证码')}</label>
          <input
            value={code}
            inputMode="numeric"
            maxLength={6}
            autoComplete="one-time-code"
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
          />
        </div>
        {err && <p className="err">{err}</p>}
        <button className="btn" style={{ marginTop: 16 }} disabled={busy || code.length !== 6} onClick={submit}>
          {busy ? t('正在验证…') : enabling ? t('验证并启用') : t('关闭双因素')}
        </button>
        {!forced && (
          <button
            style={{ display: 'block', textAlign: 'center', margin: '12px auto 0', color: '#7a7a7a', fontSize: 14, background: 'none', border: 'none', cursor: 'pointer' }}
            onClick={onDone}
          >
            {t('返回')}
          </button>
        )}
      </div>
    </>
  );
}

/* ── 修改密码 ── */function Password() {
  const [oldP, setOld] = useState('');
  const [newP, setNew] = useState('');
  const [err, setErr] = useState('');
  const [ok, setOk] = useState(false);
  const [busy, setBusy] = useState(false);
  const go = async () => {
    setBusy(true);
    setErr('');
    try {
      await api('/self/password', { method: 'POST', body: JSON.stringify({ old: oldP, new: newP }) });
      setOk(true);
      setTimeout(() => (window.location.href = '/portal'), 1600);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  if (ok)
    return (
      <div className="card" style={{ textAlign: 'center', padding: '40px 20px' }}>
        {t('密码已修改。正在跳转登录…')}
      </div>
    );
  return (
    <>
      <h2 className="h">{t('修改密码')}</h2>
      <p className="sub">{t('修改后需要重新登录')}</p>
      <div className="card">
        <div className="field">
          <label>{t('当前密码')}</label>
          <input type="password" value={oldP} autoComplete="current-password" onChange={(e) => setOld(e.target.value)} />
        </div>
        <div className="field">
          <label>{t('新密码（至少 8 位）')}</label>
          <input type="password" value={newP} autoComplete="new-password" onChange={(e) => setNew(e.target.value)} />
        </div>
        {err && <p className="err">{err}</p>}
        <button className="btn" style={{ marginTop: 18 }} disabled={busy} onClick={go}>
          {busy ? t('正在保存…') : t('保存新密码')}
        </button>
      </div>
    </>
  );
}

/* ── 应用外壳 ── */
const ICONS: Record<string, string> = {
  home: 'M12 3l9 8h-3v9h-5v-6h-2v6H6v-9H3z',
  devices: 'M4 5h16v10H4zM2 18h20v2H2z',
  usage: 'M4 19V5h2v12h16v2zM8 16V9h2v7zM12 16V6h2v10zM16 16v-4h2v4z',
  me: 'M12 12a4 4 0 100-8 4 4 0 000 8zm0 2c-4 0-7 2-7 4.5V21h14v-2.5c0-2.5-3-4.5-7-4.5z',
  downloads: 'M12 3v10m0 0l-4-4m4 4l4-4M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2',
};

function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [brand, setBrand] = useState<{ company_name: string; product_name: string }>({
    company_name: '',
    product_name: '',
  });
  const [usage, setUsage] = useState<{ total_in: number; total_out: number } | null>(null);
  // 本地账号直达通道：/portal#local（跳过扫码重定向，显示本地登录表单）
  const [view, setView] = useState<string>(window.location.hash === '#local' ? 'local' : 'home');
  const [booted, setBooted] = useState(false);

  const refreshMe = () => {
    // 不捕获 view（避免过期闭包）；local 免登录视图的跳过逻辑在挂载 effect 中
    api<Me>('/self/me')
      .then((d) => {
        setMe(d);
        if (!d.onboarded) setView((v) => (v === 'home' ? 'onboarding' : v));
      })
      .catch(() => {})
      .finally(() => setBooted(true));
  };
  // 「我的」页自助断开（DSF-5）：POST /self/disconnect 服务端踢线下线并即时 settle 台账
  const [dcBusy, setDcBusy] = useState(false);
  const [dcHint, setDcHint] = useState('');
  const disconnect = async () => {
    setDcBusy(true);
    setDcHint('');
    try {
      // 直连固定端点（POST，同源 cookie）：断开是乐观下线操作，不走会话请求封装，
      // 失败路径（401/业务码）就地处理，不触发统一封装的登录跳转副作用
      const resp = await fetch('/api/v1/self/disconnect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
      });
      if (resp.status === 401) {
        window.location.href = '/api/v1/self/login';
        throw new Error('unauthorized');
      }
      const body = await resp.json();
      if (body.code !== 0) throw new Error(body.message || t('请求失败'));
      setDcHint(t('已断开连接，可重新一键连接。'));
      refreshMe();
    } catch (e) {
      alert((e as Error).message);
    } finally {
      setDcBusy(false);
    }
  };
  // 挂载即拉取身份；local 免登录视图不发起会话请求（无 JWT，会 401 弹登录），直接完成启动
  useEffect(() => {
    if (view === 'local') {
      setBooted(true);
      return;
    }
    refreshMe();
  }, []);
  useEffect(() => {
    fetch(API + '/self/branding')
      .then((r) => r.json())
      .then((b) => {
        if (b.code === 0 && b.data && b.data.product_name) {
          setBrand(b.data);
          document.title = (b.data.product_name || t('员工门户')) + ' · ' + t('员工门户');
        }
      })
      .catch(() => {});
  }, []);
  useEffect(() => {
    if (me) api<{ total_in: number; total_out: number }>('/self/usage').then(setUsage).catch(() => {});
  }, [me]);
  // 在线状态保鲜：页面可见时每 20s 轮询 /self/me，切回页面立即刷新——
  // 否则客户端断开后页面一直显示陈旧的"已连接"（曾致用户报障）
  useEffect(() => {
    if (!me) return;
    const tick = () => {
      if (document.visibilityState !== 'visible') return;
      api<Me>('/self/me')
        .then((d) => {
          setMe((cur) => (cur ? { ...cur, online: d.online, virtual_ip: d.virtual_ip, device_used: d.device_used } : d));
        })
        .catch(() => {});
    };
    const timer = window.setInterval(tick, 20000);
    const onFocus = () => tick();
    window.addEventListener('focus', onFocus);
    document.addEventListener('visibilitychange', onFocus);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener('focus', onFocus);
      document.removeEventListener('visibilitychange', onFocus);
    };
  }, [me ? me.username : '']);

  const logout = async () => {
    // 三步退出：①清除 adapter 免扫码浏览器会话（modsec_web_sess，否则 8h 内会被静默重登）
    // ②清除门户会话 ③回门户（401 时 api 封装自动带出登录页）
    await fetch('/logout-web-sess', { credentials: 'same-origin' }).catch(() => {});
    await fetch(API + '/self/logout', { method: 'POST', credentials: 'same-origin' }).catch(() => {});
    window.location.href = '/portal';
  };

  if (!booted) return <div style={{ textAlign: 'center', padding: 80, color: '#7a7a7a' }}>{t('加载中…')}</div>;
  if (view === 'local') return <LoginLocal onDone={() => setView('home')} />;

  // 双因素强制态（租户策略命中且未绑定）：整个门户只剩绑定闭环（me 每次取自服务端，实时判定）
  if (me && me.totp_required && !me.totp_enabled) {
    return (
      <>
        <style>{css}</style>
        <div className="top">
          <div className="logo">
            <svg viewBox="0 0 120 120" width="100%" height="100%" role="img" aria-label="Modsafe">
              <polygon points="20,34 86,34 100,20 34,20" fill="#3B82F6" />
              <polygon points="86,34 100,20 100,86 86,100" fill="#12307A" />
              <rect x="20" y="34" width="66" height="66" fill="#1D4ED8" />
              <path d="M37 44 H69 C71.21 44 73 45.79 73 48 V67 C73 78 66 84 53 89 C40 84 33 78 33 67 V48 C33 45.79 34.79 44 37 44 Z" fill="#FFFFFF" />
            </svg>
          </div>
          <div className="brand">
            {brand.product_name || t('员工门户')}
            <small>{t('安全验证')}</small>
          </div>
          <button className="logout" onClick={logout}>
            {t('退出')}
          </button>
        </div>
        <Totp me={me} forced onDone={refreshMe} />
      </>
    );
  }

  const tab = (v: string, label: string) => (
    <button key={v} className={view === v || (v === 'home' && view === 'onboarding') ? 'on' : ''} onClick={() => setView(v)}>
      <svg viewBox="0 0 24 24" fill="currentColor">
        <path d={ICONS[v]} />
      </svg>
      {label}
    </button>
  );

  return (
    <>
      <style>{css}</style>
      <div className="top">
        <div className="logo">
          <svg viewBox="0 0 120 120" width="100%" height="100%" role="img" aria-label="Modsafe">
            <polygon points="20,34 86,34 100,20 34,20" fill="#3B82F6" />
            <polygon points="86,34 100,20 100,86 86,100" fill="#12307A" />
            <rect x="20" y="34" width="66" height="66" fill="#1D4ED8" />
            <path d="M37 44 H69 C71.21 44 73 45.79 73 48 V67 C73 78 66 84 53 89 C40 84 33 78 33 67 V48 C33 45.79 34.79 44 37 44 Z" fill="#FFFFFF" />
          </svg>
        </div>
        <div className="brand">
          {brand.product_name || t('员工门户')}
          <small>{me ? '@' + me.username + ' · ' + t('员工自助服务') : t('员工自助服务')}</small>
        </div>
        <button
          className="logout"
          onClick={() => setLang(currentLang() === 'zh' ? 'en' : 'zh')}
          title="Language"
        >
          {currentLang() === 'zh' ? 'EN' : '中文'}
        </button>
        <button className="logout" onClick={logout}>
          {t('退出')}
        </button>
      </div>

      {me && view === 'onboarding' && <Onboarding me={me} onDone={refreshMe} />}
      {me && view === 'home' && <Home me={me} usage={usage} go={setView} />}
      {me && view === 'devices' && <Devices refreshMe={refreshMe} me={me} />}
      {me && view === 'usage' && <Usage />}
      {me && view === 'password' && <Password />}
      {me && view === 'totp' && <Totp me={me} onDone={() => { refreshMe(); setView('me'); }} />}
      {me && view === 'downloads' && <Downloads />}
      {me && view === 'me' && (
        <>
          <PassCard me={me} usage={usage} />
          {me.online && (
            <div className="acts">
              <button className="btn red" disabled={dcBusy} onClick={disconnect}>
                {dcBusy ? t('正在断开…') : t('断开连接')}
              </button>
            </div>
          )}
          {dcHint && (
            <p className="sub" style={{ margin: '0 20px 6px', color: '#1D4ED8' }}>
              {dcHint}
            </p>
          )}
          <div className="card">
            <div className="row">
              <span className="k">{t('账号')}</span>
              <span>{me.username}</span>
            </div>
            <div className="row">
              <span className="k">{t('认证方式')}</span>
              <span>{SOURCE_LABEL()[me.source] || me.source}</span>
            </div>
            <div className="row">
              <span className="k">{t('密码管理')}</span>
              <span>{me.is_local ? t('本门户修改') : t('在企业认证源（钉钉/企微等）修改')}</span>
            </div>
            <div className="row">
              <span className="k">{t('双因素认证')}</span>
              <span>
                {me.totp_enabled
                  ? t('已启用')
                  : me.totp_required
                    ? t('待绑定（企业策略要求）')
                    : t('未启用')}
              </span>
            </div>
          </div>
          {(!me.totp_enabled || !me.totp_required) && (
            <div className="acts">
              <button className="btn ghost" onClick={() => setView('totp')}>
                {me.totp_enabled ? t('关闭双因素') : t('绑定双因素')}
              </button>
            </div>
          )}
          {me.is_local ? (
            <div className="acts">
              <button className="btn" onClick={() => setView('password')}>
                {t('修改密码')}
              </button>
            </div>
          ) : (
            <p className="sub" style={{ marginTop: 2 }}>{t('账号密码由企业认证源统一管理，如需修改请联系所在平台的账号设置。')}</p>
          )}
          <div className="acts">
            <button className="btn ghost" onClick={logout}>
              {t('退出登录')}
            </button>
          </div>
        </>
      )}

      <nav className="tabs">
        {tab('home', t('首页'))}
        {tab('devices', t('设备'))}
        {tab('usage', t('统计'))}
        {tab('downloads', t('下载'))}
        {tab('me', t('我的'))}
      </nav>
    </>
  );
}

createRoot(document.getElementById('root')!).render(<App />);
