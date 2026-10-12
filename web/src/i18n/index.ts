/* 轻量 i18n 内核（无依赖，管理台/门户共用）。
 * 设计：
 *  - zh 为基准（代码里已有的中文即 zh 文案，不维护 zh 词典）；en 走词典缺失回退 zh；
 *  - 语言解析：localStorage 显式选择 > navigator.language（zh*→zh，其余→en）；
 *  - t(key, params)：键即中文原文（免改造存量代码），params 用 {name} 插值；
 *  - 切换：setLang() 写 localStorage 并重载（门户与管理台均为整页应用，重载最简且无残留状态）。
 * 扩展新语言：新增一个 dict-<lang>.ts 并在 dictionaries 注册即可。 */
import { createContext, useContext } from 'react';

export type Lang = 'zh' | 'en';
type Dict = Record<string, string>;

const en: Dict = {
  // ── 门户：通用 ──
  '请求失败': 'Request failed',
  '下载链接已失效，请重新生成': 'Download link expired, please regenerate',
  '本地账号': 'Local account',
  '钉钉': 'DingTalk',
  '企业微信': 'WeCom',
  '飞书': 'Feishu',
  'AD 域': 'AD domain',
  // ── 门户：导航/身份卡 ──
  '首页': 'Home',
  '设备': 'Devices',
  '统计': 'Usage',
  '我的': 'Me',
  '在线': 'Online',
  '离线': 'Offline',
  // ── 门户：设备/统计/设置等长文案见 dict-en-portal.ts ──
};

// 门户与管理台分别挂接各自的大词典（按需拆文件，此处聚合）
import { enPortal } from './dict-en-portal';
import { enAdmin } from './dict-en-admin';
Object.assign(en, enPortal, enAdmin);

const DICTS: Record<Exclude<Lang, 'zh'>, Dict> = { en };

export function detectLang(): Lang {
  const saved = localStorage.getItem('modsafe_lang');
  if (saved === 'zh' || saved === 'en') return saved;
  const nav = navigator.language || '';
  return /^zh/i.test(nav) ? 'zh' : 'en';
}

export function currentLang(): Lang {
  return detectLang();
}

export function setLang(l: Lang): void {
  localStorage.setItem('modsafe_lang', l);
  window.location.reload();
}

/** 翻译：key=中文原文；缺失回退 key 本身；{name} 插值 */
export function t(key: string, params?: Record<string, string | number>): string {
  if (currentLang() === 'zh') return interp(key, params);
  const d = DICTS[detectLang() as Exclude<Lang, 'zh'>] || {};
  return interp(d[key] ?? key, params);
}

function interp(s: string, params?: Record<string, string | number>): string {
  if (!params) return s;
  return s.replace(/\{(\w+)\}/g, (_, k) => String(params[k] ?? `{${k}}`));
}

/** React 绑定：语言变更通过整页 reload 生效，Context 仅用于组件声明依赖 */
export const I18nContext = createContext<Lang>(detectLang());
export const useI18n = () => useContext(I18nContext);
