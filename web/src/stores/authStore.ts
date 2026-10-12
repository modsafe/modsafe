import { create } from 'zustand';
import type { AdminUser } from '../api/types';

interface AuthState {
  token: string | null;
  user: AdminUser | null;
  login: (token: string, user: AdminUser) => void;
  logout: () => void;
}

const TOKEN_KEY = 'modsec_admin_token';
const USER_KEY = 'modsec_admin_user';

export const useAuthStore = create<AuthState>((set) => ({
  token: localStorage.getItem(TOKEN_KEY),
  user: JSON.parse(localStorage.getItem(USER_KEY) ?? 'null'),
  login: (token, user) => {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
    set({ token, user });
  },
  logout: () => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    set({ token: null, user: null });
  },
}));

export const hasRole = (user: AdminUser | null, role: AdminUser['roles'][number]) =>
  user?.roles.includes(role) ?? false;
