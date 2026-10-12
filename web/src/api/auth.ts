import http from './client';
import type { AdminUser } from './types';

export interface LoginResult {
  token: string;
  user: AdminUser;
  must_change_password: boolean;
  /** #109：系统强制双因素且该账号未绑定 → 此 token 仅可用于 TOTP 绑定闭环 */
  totp_enroll?: boolean;
}

export function login(username: string, password: string, headers?: Record<string, string>) {
  return http.post<never, LoginResult>(
    '/auth/login',
    { username, password },
    headers && Object.keys(headers).length ? { headers } : undefined,
  );
}

export function getTotpSetup() {
  return http.get<never, { secret: string; otpauth_uri: string; enabled: boolean }>('/auth/totp/setup');
}
export function enableTotp(code: string) {
  return http.post<never, { ok: boolean }>('/auth/totp/enable', { code });
}
export function disableTotp(code: string) {
  return http.post<never, { ok: boolean }>('/auth/totp/disable', { code });
}
export function getTotpSettings() {
  return http.get<never, { enforced: boolean }>('/settings/totp');
}
export function putTotpSettings(enforced: boolean) {
  return http.put<never, { enforced: boolean }>('/settings/totp', { enforced });
}

export function logout() {
  return http.post<never, void>('/auth/logout');
}

export function getMe() {
  return http.get<never, AdminUser>('/auth/me');
}
