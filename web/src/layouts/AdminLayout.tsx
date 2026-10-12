import { App, Dropdown, Form, Input, Modal } from 'antd';
import ProLayout, { type MenuDataItem } from '@ant-design/pro-layout';
import {
  BugOutlined,
  UserOutlined,
  DesktopOutlined,
  TeamOutlined,
  ClusterOutlined,
  SafetyOutlined,
  SafetyCertificateOutlined,
  MonitorOutlined,
  FileTextOutlined,
  SettingOutlined,
  AlertOutlined,
  LogoutOutlined,
  KeyOutlined,
} from '@ant-design/icons';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useState } from 'react';
import { useAuthStore } from '../stores/authStore';
import { logout as apiLogout } from '../api/auth';
import http from '../api/client';
import { t, setLang, currentLang } from '../i18n';

/** 导航树 = §12.1 信息架构（一期 7 项可用，其余建设中禁用）；
 * 名称经 t() 实时翻译（语言切换=整页 reload，无陈旧问题） */
const menuRoute: MenuDataItem[] = [
  { path: '/dashboard', icon: <BugOutlined />, name: t('总览') },
  { path: '/organization', icon: <TeamOutlined />, name: t('用户与组织') },
  { path: '/devices', icon: <DesktopOutlined />, name: t('设备管理') },
  { path: '/resources', icon: <ClusterOutlined />, name: t('资源管理') },
  { path: '/policies', icon: <SafetyOutlined />, name: t('策略管理 (CCD)') },
  { path: '/auth/idp', icon: <SafetyCertificateOutlined />, name: t('认证管理') },
  { path: '/certificates', icon: <SafetyCertificateOutlined />, name: t('证书管理') },
  {
    path: '/monitor',
    icon: <MonitorOutlined />,
    name: t('监控中心'),
    children: [
      { path: '/monitor/sessions', name: t('在线用户') },
      { path: '/monitor/traffic', name: t('流量看板') },
      { path: '/monitor/audit', name: t('流量审计') },
      { path: '/monitor/nodes', name: t('节点状态') },
    ],
  },
  { path: '/alerts', icon: <AlertOutlined />, name: t('告警中心') },
  {
    path: '/audit',
    icon: <FileTextOutlined />,
    name: t('审计日志'),
    children: [
      { path: '/audit/auth-logs', name: t('认证日志') },
      { path: '/audit/session-logs', name: t('会话日志') },
      { path: '/audit/admin-logs', name: t('管理操作') },
    ],
  },
  { path: '/settings', icon: <SettingOutlined />, name: t('系统设置') },
];

export default function AdminLayout() {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuthStore();
  const { message } = App.useApp();
  const [pwdOpen, setPwdOpen] = useState(false);
  const [pwdSaving, setPwdSaving] = useState(false);
  const [pwdForm] = Form.useForm();

  const handleLogout = async () => {
    try {
      await apiLogout();
    } catch {
      /* 服务端登出失败不阻塞本地登出 */
    }
    logout();
    navigate('/login', { replace: true });
  };

  const changePassword = async () => {
    const v = await pwdForm.validateFields();
    setPwdSaving(true);
    try {
      await http.post('/auth/change-password', { old_password: v.old_password, new_password: v.new_password });
      setPwdOpen(false);
      pwdForm.resetFields();
      message.success(t('密码已修改，请使用新密码重新登录'));
      setTimeout(() => {
        logout();
        navigate('/login', { replace: true });
      }, 1200);
    } catch {
      /* 拦截器已提示（旧密码错误/强度不足） */
    } finally {
      setPwdSaving(false);
    }
  };

  return (
    <ProLayout
      title={t('模方安全 管理台')}
      logo={
        <svg viewBox="0 0 120 120" width="30" height="30" role="img" aria-label="Modsafe">
          <polygon points="20,34 86,34 100,20 34,20" fill="#3B82F6" />
          <polygon points="86,34 100,20 100,86 86,100" fill="#12307A" />
          <rect x="20" y="34" width="66" height="66" fill="#1D4ED8" />
          <path d="M37 44 H69 C71.21 44 73 45.79 73 48 V67 C73 78 66 84 53 89 C40 84 33 78 33 67 V48 C33 45.79 34.79 44 37 44 Z" fill="#FFFFFF" />
        </svg>
      }
      layout="mix"
      fixSiderbar
      location={{ pathname: location.pathname }}
      menu={{ request: async () => menuRoute }}
      menuItemRender={(item, dom) => (
        <a onClick={() => item.path && navigate(item.path)}>{dom}</a>
      )}
      actionsRender={() => [
        <a
          key="lang"
          onClick={() => setLang(currentLang() === 'zh' ? 'en' : 'zh')}
          style={{ padding: '0 12px', cursor: 'pointer' }}
        >
          {currentLang() === 'zh' ? 'EN' : '中文'}
        </a>,
      ]}
      avatarProps={{
        icon: <UserOutlined />,
        size: 'small',
        title: user?.username ?? t('管理员'),
        render: (_props, dom) => (
          <Dropdown
            menu={{
              items: [
                { key: 'change-password', icon: <KeyOutlined />, label: t('修改密码') },
                { type: 'divider' },
                { key: 'logout', icon: <LogoutOutlined />, label: t('退出登录') },
              ],
              onClick: ({ key }) => {
                if (key === 'logout') handleLogout();
                if (key === 'change-password') setPwdOpen(true);
              },
            }}
          >
            {dom}
          </Dropdown>
        ),
      }}
    >
      <Modal
        title={t('修改密码')}
        open={pwdOpen}
        onOk={changePassword}
        onCancel={() => setPwdOpen(false)}
        confirmLoading={pwdSaving}
        destroyOnClose
      >
        <Form form={pwdForm} layout="vertical">
          <Form.Item label={t('旧密码')} name="old_password" rules={[{ required: true, message: t('请输入旧密码') }]}>
            <Input.Password autoComplete="current-password" />
          </Form.Item>
          <Form.Item
            label={t('新密码')}
            name="new_password"
            rules={[
              { required: true, message: t('请输入新密码') },
              { min: 8, message: t('长度不能少于 8 位') },
            ]}
            extra={t('至少 8 位；修改成功后需使用新密码重新登录')}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item
            label={t('确认新密码')}
            name="confirm"
            dependencies={['new_password']}
            rules={[
              { required: true, message: t('请再次输入新密码') },
              ({ getFieldValue }) => ({
                validator: (_, v) =>
                  !v || v === getFieldValue('new_password')
                    ? Promise.resolve()
                    : Promise.reject(new Error(t('两次输入的新密码不一致'))),
              }),
            ]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
        </Form>
      </Modal>
      <Outlet />
    </ProLayout>
  );
}
