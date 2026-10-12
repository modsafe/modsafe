import { Button, Card, Form, Input, Typography, App } from 'antd';
import { SafetyCertificateOutlined } from '@ant-design/icons';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { enableTotp, getTotpSetup, logout } from '../../api/auth';
import { useAuthStore } from '../../stores/authStore';
import { t } from '../../i18n';

/** #109：系统强制双因素下的首登绑定页（token 仅含绑定权限，绑定成功后重新登录） */
export default function Enroll() {
  const navigate = useNavigate();
  const doLogout = useAuthStore((s) => s.logout);
  const { message } = App.useApp();
  const [state, setState] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);

  const fetchSecret = () => {
    getTotpSetup().then((d: { secret: string; otpauth_uri: string }) =>
      setState({ secret: d.secret, otpauth_uri: d.otpauth_uri }),
    );
  };

  const bind = () => {
    setLoading(true);
    enableTotp(code)
      .then(() => {
        message.success(t('双因素绑定完成，请重新登录并输入动态验证码'));
        doLogout();
        navigate('/login', { replace: true });
      })
      .catch(() => {
        // 错误文案由 client.ts 拦截器统一提示
      })
      .finally(() => setLoading(false));
  };

  const quit = () => {
    logout().finally(() => {
      doLogout();
      navigate('/login', { replace: true });
    });
  };

  return (
    <div style={{ height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#f0f2f5' }}>
      <Card style={{ width: 420 }}>
        <Typography.Title level={4} style={{ textAlign: 'center' }}>
          {t('绑定双因素认证')}
        </Typography.Title>
        <Typography.Paragraph type="secondary" style={{ textAlign: 'center', fontSize: 13 }}>
          {t('系统已强制双因素认证：请使用验证器 App 扫描或手动录入下方密钥，输入 6 位动态码完成绑定后重新登录。')}
        </Typography.Paragraph>
        {!state && (
          <div style={{ textAlign: 'center' }}>
            <Button type="primary" onClick={fetchSecret}>
              {t('获取绑定密钥')}
            </Button>
          </div>
        )}
        {state && (
          <>
            <Typography.Paragraph copyable={{ text: state.otpauth_uri }} style={{ wordBreak: 'break-all', fontSize: 12 }}>
              {state.otpauth_uri}
            </Typography.Paragraph>
            <Form layout="vertical">
              <Form.Item>
                <Input
                  prefix={<SafetyCertificateOutlined />}
                  placeholder={t('6 位动态验证码')}
                  maxLength={6}
                  inputMode="numeric"
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                  size="large"
                />
              </Form.Item>
              <Button type="primary" block size="large" loading={loading} disabled={code.length !== 6} onClick={bind}>
                {t('验证并完成绑定')}
              </Button>
            </Form>
          </>
        )}
        <a onClick={quit} style={{ display: 'block', textAlign: 'center', marginTop: 12, color: '#999' }}>
          {t('暂不绑定，退出登录')}
        </a>
      </Card>
    </div>
  );
}
