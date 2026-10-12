export type IdpSource = 'local' | 'ldap' | 'ldap-ad' | 'dingtalk' | 'wecom' | 'feishu';
export type UserStatus = 'active' | 'disabled';

export interface User {
  id: number;
  username: string;
  display_name: string;
  email: string;
  source: IdpSource;
  status: UserStatus;
  groups: { id: number; name: string }[];
  device_quota: number;
  totp_enabled: number;
  created_at: string;
  last_login_at: string;
}

export interface Group {
  id: number;
  name: string;
  member_count: number;
  resource_count: number;
  idp_ref: string;
  created_at: string;
}

export interface Resource {
  id: number;
  name: string;
  cidr: string;
  description: string;
  ref_count: number;
}

export interface CcdRule {
  id: number;
  name: string;
  type: 'route' | 'dns' | 'redirect_gateway' | 'iroute' | 'route_metric';
  value: string;
  priority: number;
  scope: 'global' | 'group' | 'user';
  group_id: number | null;
  user_id: number | null;
  enabled: boolean;
  updated_at: string;
}

export interface SessionItem {
  username: string;
  virtual_ip: string;
  trusted_ip: string;
  connected_at: string;
  bytes_in: number;
  bytes_out: number;
  node: string;
}

export interface AdminUser {
  id: number;
  username: string;
  roles: ('super_admin' | 'security_admin' | 'auditor')[];
}
