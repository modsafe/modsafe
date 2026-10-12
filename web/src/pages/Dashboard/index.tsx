import { PageContainer } from '@ant-design/pro-components';
import { t } from '../../i18n';
import { Button, Card, Col, Modal, Popconfirm, Row, Statistic } from 'antd';
import {
  LinkOutlined,
  TeamOutlined,
  AlertOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import ReactECharts from 'echarts-for-react';
import http from '../../api/client';
import { useAuthStore } from '../../stores/authStore';

interface Summary {
  online_users: number;
  today_connections: number;
  total_users: number;
  active_users: number;
  pending_alerts: number;
  cert_days_left: number;
  certs: { file: string; days_left: number }[];
  collector: boolean;
}

export default function Dashboard() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [trend, setTrend] = useState<{ time: string; online: number }[]>([]);
  const [renewing, setRenewing] = useState(false);
  const navigate = useNavigate();
  const isSuper = !!useAuthStore((s) => s.user?.roles?.includes('super_admin'));

  const loadSummary = () => http.get<never, Summary>('/dashboard/summary').then(setSummary).catch(() => {});

  useEffect(() => {
    loadSummary();
    http.get<never, { time: string; online: number }[]>('/dashboard/trend').then(setTrend).catch(() => {});
    const t = setInterval(() => {
      http.get<never, Summary>('/dashboard/summary').then(setSummary).catch(() => {});
    }, 30000);
    return () => clearInterval(t);
  }, []);

  const doRenew = async () => {
    setRenewing(true);
    try {
      const d = await http.post<never, { not_after: string; node2_hint: string }>('/settings/cert/server-renew');
      Modal.success({
        title: t('服务端证书已续期'),
        width: 560,
        content: (
          <div style={{ textAlign: 'left', fontSize: 13 }}>
            <p>{t('新有效期至')}: {d.not_after}</p>
            <p>{d.node2_hint}</p>
          </div>
        ),
      });
      loadSummary();
    } catch {
      /* 拦截器已提示 */
    } finally {
      setRenewing(false);
    }
  };

  const doRenewCA = async () => {
    setRenewing(true);
    try {
      const d = await http.post<never, { ca_not_after: string; server_not_after: string; subca_not_after: string; node2_hint: string }>('/settings/cert/ca-renew');
      Modal.success({
        title: t('CA 证书已续期（全链重签）'),
        width: 620,
        content: (
          <div style={{ textAlign: 'left', fontSize: 13 }}>
            <p>{t('新有效期至')}：</p>
            <ul style={{ margin: '4px 0', paddingLeft: 20 }}>
              <li>{t('CA 证书')}: {d.ca_not_after}</li>
              <li>{t('服务端证书')}: {d.server_not_after}</li>
              <li>{t('客户端子 CA')}: {d.subca_not_after}</li>
            </ul>
            <p>{d.node2_hint}</p>
          </div>
        ),
      });
      loadSummary();
    } catch {
      /* 拦截器已提示 */
    } finally {
      setRenewing(false);
    }
  };

  const trendOption = {
    tooltip: { trigger: 'axis' },
    xAxis: { type: 'category', data: trend.map((p) => p.time) },
    yAxis: { type: 'value', minInterval: 1 },
    series: [
      {
        name: t('在线用户'),
        type: 'line',
        smooth: true,
        showSymbol: false,
        data: trend.map((p) => p.online),
        areaStyle: { opacity: 0.15 },
      },
    ],
  };

  const s = summary;
  // #133：证书拆分显示——服务端证书（可续期）与 CA 证书（到期走厂商流程）口径不同，必须分开
  const serverCert = s?.certs?.find((c) => c.file === 'server.crt');
  const caCert = s?.certs?.find((c) => c.file === 'ca.crt');
  // #132：统计卡点击跳转对应页面（在线用户→会话监控；今日连接→认证日志；启用用户→组织与用户；告警→告警中心）
  const statCards: { title: string; value: string | number; prefix: React.ReactNode; to: string; valueStyle?: React.CSSProperties }[] = [
    {
      title: t('当前在线用户'),
      value: s?.online_users ?? '-',
      prefix: <LinkOutlined />,
      to: '/monitor/sessions',
    },
    {
      title: t('今日连接数'),
      value: s?.today_connections ?? '-',
      prefix: <LinkOutlined />,
      to: '/audit/auth-logs',
    },
    {
      title: t('启用用户数'),
      value: s ? `${s.active_users}/${s.total_users}` : '-',
      prefix: <TeamOutlined />,
      to: '/organization',
    },
    {
      title: t('待处理告警'),
      value: s?.pending_alerts ?? '-',
      prefix: <AlertOutlined />,
      to: '/alerts',
      valueStyle: { color: (s?.pending_alerts ?? 0) > 0 ? '#cf1322' : '#52c41a' },
    },
  ];
  return (
    <PageContainer title={t('总览')} subTitle={t('集群运行状态与连接趋势（30s 自动刷新）')}>
      <Row gutter={16}>
        {statCards.map((c) => (
          <Col xs={12} sm={6} key={c.to}>
            <Card
              hoverable
              style={{ cursor: 'pointer' }}
              onClick={() => navigate(c.to)}
            >
              <Statistic title={c.title} value={c.value} prefix={c.prefix} valueStyle={c.valueStyle} />
            </Card>
          </Col>
        ))}
      </Row>
      <Card title={t('24 小时在线趋势')} style={{ marginTop: 16 }}>
        <ReactECharts option={trendOption} style={{ height: 320 }} />
      </Card>
      <Card title={t('证书有效期')} style={{ marginTop: 16 }} bordered>
        <Row gutter={16}>
          <Col xs={24} sm={12}>
            <Statistic
              title={t('服务端证书')}
              value={serverCert?.days_left ?? '-'}
              suffix={t('天')}
              prefix={<SafetyCertificateOutlined />}
              valueStyle={serverCert && serverCert.days_left < 30 ? { color: '#cf1322' } : undefined}
            />
            {isSuper && (
              <Popconfirm
                title={t('确认续期服务端证书？')}
                description={t('续期会用同一 CA 重签证书并重载节点 1 的接入服务（在线会话瞬断自动重连），完成后按提示同步节点 2。')}
                onConfirm={doRenew}
              >
                <Button type="primary" size="small" loading={renewing} style={{ marginTop: 12 }}>
                  {t('续期服务端证书')}
                </Button>
              </Popconfirm>
            )}
          </Col>
          <Col xs={24} sm={12}>
            <Statistic
              title={t('CA 证书')}
              value={caCert?.days_left ?? '-'}
              suffix={t('天')}
              valueStyle={caCert && caCert.days_left < 90 ? { color: '#cf1322' } : undefined}
            />
            {isSuper && (
              <Popconfirm
                title={t('确认续期 CA 证书？')}
                description={t('全链重签：root CA、服务端证书与客户端子 CA 全部沿用原私钥换发（主题改为 Modsafe），并重载节点 1（会话瞬断自动重连）。')}
                onConfirm={doRenewCA}
              >
                <Button type="primary" size="small" loading={renewing} style={{ marginTop: 12 }}>
                  {t('续期 CA 证书（全链重签）')}
                </Button>
              </Popconfirm>
            )}
          </Col>
        </Row>
        <p style={{ fontSize: 12, color: '#6e6e73', marginTop: 16, marginBottom: 0 }}>
          {t('服务端证书到期会导致全员无法连接——剩余不足 30 天请及时续期（同 CA 重签，已下发配置无需更新）。CA 证书续期后请通知所有用户重新下载配置（旧配置在旧 CA 到期前仍可用，平滑过渡）。')}
        </p>
      </Card>
    </PageContainer>
  );
}
