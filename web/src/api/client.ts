import axios, { AxiosError } from 'axios';
import { message } from 'antd';
import { useAuthStore } from '../stores/authStore';

/** 统一返回体（§12.4 规范） */
export interface ApiEnvelope<T> {
  code: number;
  message: string;
  data: T;
  traceId?: string;
}

/** 统一分页结构（§12.4 规范） */
export interface PageData<T> {
  list: T[];
  total: number;
  page: number;
  pageSize: number;
}

/** 错误码 → 文案（§12.4 错误码表；未命中回退服务端 message） */
const ERROR_TEXT: Record<number, string> = {
  10001: '参数校验失败',
  10002: 'CIDR 格式不合法',
  20001: '用户不存在',
  20002: '设备数量已达配额上限',
  20003: '规则存在冲突',
  20004: '组内仍有成员，无法删除',
  20007: 'License 配额不足，请联系厂商扩容',
  20008: 'License 已过期',
  30001: '登录已过期，请重新登录',
  30002: '无权限执行此操作',
  30003: '账号已被禁用',
  30004: '用户名或密码错误',
  50001: '系统内部错误，请联系管理员',
  50002: '数据库暂不可用',
  50003: '节点管理接口不可达',
  50004: '依赖服务暂不可用',
};

const http = axios.create({
  baseURL: '/api/v1',
  timeout: 15000,
});

/** traceId 生成：crypto.randomUUID 仅安全上下文(https/localhost)可用，
 *  http://内网IP 下为 undefined——必须回退到 getRandomValues（全上下文可用） */
function genTraceId(): string {
  const b = new Uint8Array(16);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(b);
  } else {
    for (let i = 0; i < b.length; i++) b[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

http.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token;
  if (token) config.headers.Authorization = `Bearer ${token}`;
  config.headers['X-Trace-Id'] = genTraceId();
  return config;
});

http.interceptors.response.use(
  (resp) => {
    // Blob 响应（CSV 导出等二进制）：无统一返回体，直接透出，跳过 envelope 解包
    //（否则 body.code 为 undefined≠0 → 恒弹"请求失败"并中断下载，2026-10-08 修复）
    if (resp.config.responseType === 'blob') {
      return resp.data as never;
    }
    const body = resp.data as ApiEnvelope<unknown>;
    if (body.code !== 0) {
      if (body.code === 30001) {
        useAuthStore.getState().logout();
        if (!window.location.hash.startsWith('#/login')) {
          window.location.hash = '#/login';
        }
      }
      // axios 拦截器非 React 上下文，用 antd 静态方法（不继承主题，功能一致）
      // 服务端 message 优先（具体原因，如续期失败的文件错误），映射表兜底——
      // 映射表按错误码统一文案会吞掉服务端精确原因（30004/50001 都吃过这亏）
      message.error(body.message || ERROR_TEXT[body.code] || '请求失败');
      return Promise.reject(body);
    }
    // 解包统一返回体，调用方直接拿 data
    return body.data as never;
  },
  (err: AxiosError) => {
    // 非 2xx 也可能是合法 envelope（业务错误带 4xx/5xx 状态）：优先透出服务端文案
    const body = err.response?.data as ApiEnvelope<unknown> | undefined;
    if (body && typeof body.code === 'number') {
      if (body.code === 30001) {
        useAuthStore.getState().logout();
        if (!window.location.hash.startsWith('#/login')) {
          window.location.hash = '#/login';
        }
      }
      // 服务端 message 优先（具体原因，如续期失败的文件错误），映射表兜底——
      // 映射表按错误码统一文案会吞掉服务端精确原因（30004/50001 都吃过这亏）
      message.error(body.message || ERROR_TEXT[body.code] || '请求失败');
      return Promise.reject(new Error(body.message || '请求失败'));
    }
    message.error('网络异常，请稍后重试');
    return Promise.reject(err);
  },
);

export default http;
