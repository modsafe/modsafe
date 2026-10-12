import { Form, Input, Button, Card, Typography, App } from 'antd';
import { UserOutlined, LockOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { useState } from 'react';
import { login } from '../../api/auth';
import { useAuthStore } from '../../stores/authStore';
import { t, setLang, currentLang } from '../../i18n';

export default function Login() {
  const navigate = useNavigate();
  const doLogin = useAuthStore((s) => s.login);
  const { message } = App.useApp();
  const [loading, setLoading] = useState(false);
  // P1-e：账号密码通过但缺/错 TOTP 时，后端报"动态验证码"——展开验证码输入
  const [totpMode, setTotpMode] = useState(false);

  const onFinish = async (values: { username: string; password: string; totp_code?: string }) => {
    setLoading(true);
    try {
      const headers: Record<string, string> = {};
      if (values.totp_code) headers['X-TOTP-Code'] = values.totp_code;
      const result = await login(values.username, values.password, headers);
      // #109：系统强制双因素且未绑定 → 限定 token，进入绑定页
      if (result.totp_enroll) {
        doLogin(result.token, result.user);
        message.info(t('请先完成双因素绑定'));
        navigate('/enroll', { replace: true });
        return;
      }
      doLogin(result.token, result.user);
      message.success(t('登录成功'));
      navigate('/dashboard', { replace: true });
    } catch (e) {
      const msg = e instanceof Error ? e.message : '';
      if (msg.includes('动态验证码')) {
        setTotpMode(true);
      }
      // 其余错误文案已由 client.ts 拦截器统一提示（含 30004 锁定倒计时）
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        height: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: '#f0f2f5',
      }}
    >
      <Card style={{ width: 380 }}>
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 16 }}>
          <svg viewBox="0 0 120 120" width="64" height="64" role="img" aria-label="Modsafe">
            <polygon points="20,34 86,34 100,20 34,20" fill="#3B82F6" />
            <polygon points="86,34 100,20 100,86 86,100" fill="#12307A" />
            <rect x="20" y="34" width="66" height="66" fill="#1D4ED8" />
            <path d="M37 44 H69 C71.21 44 73 45.79 73 48 V67 C73 78 66 84 53 89 C40 84 33 78 33 67 V48 C33 45.79 34.79 44 37 44 Z" fill="#FFFFFF" />
          </svg>
        </div>
        <Typography.Title level={3} style={{ textAlign: 'center', marginBottom: 24 }}>
          {t('模方安全 管理台')}
        </Typography.Title>
        <Form onFinish={onFinish} size="large">
          <Form.Item name="username" rules={[{ required: true, message: t('请输入用户名') }]}>
            <Input prefix={<UserOutlined />} placeholder={t('管理员账号')} autoFocus={!totpMode} />
          </Form.Item>
          <Form.Item name="password" rules={[{ required: true, message: t('请输入密码') }]}>
            <Input.Password prefix={<LockOutlined />} placeholder={t('密码')} autoFocus={totpMode} />
          </Form.Item>
          {totpMode && (
            <Form.Item
              name="totp_code"
              rules={[{ required: true, message: t('请输入 6 位动态验证码') }]}
            >
              <Input
                prefix={<SafetyCertificateOutlined />}
                placeholder={t('动态验证码（6 位）')}
                maxLength={6}
                inputMode="numeric"
              />
            </Form.Item>
          )}
          <Form.Item style={{ marginBottom: 0 }}>
            <Button type="primary" htmlType="submit" block loading={loading}>
              {t('登 录')}
            </Button>
          </Form.Item>
        </Form>
        <Typography.Text type="secondary" style={{ display: 'block', textAlign: 'center', marginTop: 16 }}>
          {totpMode ? t('请输入验证器 App 中的 6 位动态码') : t('初始账号见安装摘要，首次登录强制修改密码')}
        </Typography.Text>
        <a
          onClick={() => setLang(currentLang() === 'zh' ? 'en' : 'zh')}
          style={{ display: 'block', textAlign: 'center', marginTop: 8, cursor: 'pointer' }}
        >
          {currentLang() === 'zh' ? 'English' : '中文'}
        </a>
      </Card>
    </div>
  );
}
