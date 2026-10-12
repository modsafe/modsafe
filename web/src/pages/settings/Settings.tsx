import { PageContainer } from '@ant-design/pro-components';
import { t } from '../../i18n';
import {
  Alert,
  Button,
  Card,
  Col,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Row,
  Select,
  Switch,
  Tabs,
  Table,
  Tag,
  App,
  Space,
  Statistic,
  Typography,
  message,
} from 'antd';
import { PlusOutlined, SoundOutlined } from '@ant-design/icons';
import { useEffect, useRef, useState } from 'react';
import QRCode from 'qrcode';
import http from '../../api/client';
import { useAuthStore } from '../../stores/authStore';

// 品牌保存后端会联动渲染 oa2 模板并重启（~10s），单请求放宽超时
const httpSlow = { timeout: 35000 };

interface BrandingForm {
  company_name: string;
  product_name: string;
  footer_text: string;
  vpn_remote: string;
  portal_base: string;
}
interface ChannelItem {
  id: string;
  type: string;
  name: string;
  webhook: string;
  enabled: boolean;
}

/** Tab 1：品牌与接入 */
function BrandingPanel() {
  const [form] = Form.useForm<BrandingForm>();
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    http
      .get<never, { branding: Partial<BrandingForm>; vpn_remote: string; portal_base: string }>('/settings/general')
      .then((d) =>
        form.setFieldsValue({
          company_name: d.branding.company_name ?? '',
          product_name: d.branding.product_name ?? '',
          footer_text: d.branding.footer_text ?? '',
          vpn_remote: d.vpn_remote,
          portal_base: d.portal_base,
        }),
      )
      .catch(() => {});
  }, [form]);

  const save = async (v: BrandingForm) => {
    setLoading(true);
    try {
      await http.put('/settings/general', v, httpSlow);
      message.success(t('已保存：品牌即时生效（登录页已重渲染），接入地址对新签发的 .ovpn 生效'));
    } catch {
      /* 拦截器已提示 */
    } finally {
      setLoading(false);
    }
  };

  return (
    <Form form={form} layout="vertical" style={{ maxWidth: 560 }} onFinish={save}>
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message={t('品牌信息用于扫码登录页（公司名/产品名/页脚）；接入地址写入新生成的客户端 .ovpn 的 remote 行')}
      />
      <Form.Item label={t('公司名')} name="company_name" rules={[{ max: 128, message: '不超过 128 字符' }]}>
        <Input placeholder={t('如：某某科技')} />
      </Form.Item>
      <Form.Item label={t('产品名')} name="product_name" rules={[{ max: 128, message: '不超过 128 字符' }]}>
        <Input placeholder={t('如：模方安全')} />
      </Form.Item>
      <Form.Item label={t('登录页页脚')} name="footer_text" rules={[{ max: 128, message: '不超过 128 字符' }]}>
        <Input placeholder={t('如：IT 支持：it@company.com')} />
      </Form.Item>
      <Form.Item
        label={t('客户端接入地址（remote）')}
        name="vpn_remote"
        extra={t('格式：地址 端口。HA 集群填 VIP；修改仅影响之后生成的 .ovpn，已分发配置不受影响')}
        rules={[
          {
            validator: (_, v: string) =>
              !v || /^[^\s]+\s+[0-9]{1,5}$/.test(v.trim())
                ? Promise.resolve()
                : Promise.reject(new Error(t('格式：地址 端口（如 vpn.example.com 1194）'))),
          },
        ]}
      >
        <Input placeholder="vpn.example.com 1194" />
      </Form.Item>
      <Form.Item
        label={t('门户地址')}
        name="portal_base"
        extra={t('新装客户端/安装包引导页使用的门户入口；launcher 将在下次一键连接时自动跟随新地址（无需重编译）')}
        rules={[
          {
            validator: (_, v: string) =>
              !v || /^https?:\/\/[^/]+\s*$/.test(v.trim())
                ? Promise.resolve()
                : Promise.reject(new Error(t('格式：https://主机[:端口]，不带路径'))),
          },
        ]}
      >
        <Input placeholder="https://portal.example.com" />
      </Form.Item>
      <Button type="primary" htmlType="submit" loading={loading}>
        保存（品牌变更将自动重启认证服务，约 10 秒）
      </Button>
    </Form>
  );
}

/** Tab 2：通知渠道（webhook） */
function ChannelsPanel() {
  const [channels, setChannels] = useState<ChannelItem[]>([]);
  const [open, setOpen] = useState(false);
  const [form] = Form.useForm<ChannelItem>();
  const [testing, setTesting] = useState(false);

  const load = () =>
    http
      .get<never, { channels: ChannelItem[] }>('/settings/notify-channels')
      .then((d) => setChannels(d.channels ?? []))
      .catch(() => {});

  useEffect(() => {
    load();
  }, []);

  const save = async () => {
    const v = await form.validateFields();
    await http.post('/settings/notify-channels', { ...v, id: undefined });
    message.success(t('渠道已保存'));
    setOpen(false);
    form.resetFields();
    load();
  };

  const del = async (id: string) => {
    await http.delete(`/settings/notify-channels/${id}`);
    message.success(t('已删除'));
    load();
  };

  const test = async () => {
    setTesting(true);
    try {
      const out = await http.post<never, { results?: unknown[] }>('/settings/notify-channels/test');
      message.success(t('测试告警已发送（{v0} 个结果，详见渠道群）', { v0: out.results?.length ?? 0 }));
    } catch {
      /* 拦截器已提示 */
    } finally {
      setTesting(false);
    }
  };

  return (
    <>
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message={t('告警渠道（节点宕机/证书到期等）。企业微信/钉钉/飞书群机器人 webhook 或通用 webhook')}
      />
      <Table<ChannelItem>
        rowKey="id"
        size="small"
        pagination={false}
        dataSource={channels}
        locale={{ emptyText: t('暂无渠道') }}
        columns={[
          { title: t('名称'), dataIndex: 'name' },
          { title: t('类型'), dataIndex: 'type', render: (_, r) => <Tag>{r.type}</Tag> },
          { title: t('启用'), dataIndex: 'enabled', render: (_, r) => (r.enabled ? <Tag color="green">{t('启用')}</Tag> : <Tag>{t('停用')}</Tag>) },
          { title: 'Webhook', dataIndex: 'webhook', ellipsis: true, width: '40%' },
          {
            title: t('操作'),
            render: (_, r) => (
              <Popconfirm title={t('删除渠道「{v0}」？', { v0: r.name })} onConfirm={() => del(r.id)}>
                <a style={{ color: '#cf1322' }}>{t('删除')}</a>
              </Popconfirm>
            ),
          },
        ]}
      />
      <div style={{ marginTop: 16 }}>
        <Button icon={<PlusOutlined />} onClick={() => setOpen(true)}>
          新增渠道
        </Button>
        <Button icon={<SoundOutlined />} style={{ marginLeft: 8 }} loading={testing} onClick={test}>
          发送测试告警
        </Button>
      </div>
      <Modal title={t('新增通知渠道')} open={open} onOk={save} onCancel={() => setOpen(false)} destroyOnClose>
        <Form form={form} layout="vertical" initialValues={{ type: 'wecom', enabled: true }}>
          <Form.Item label={t('类型')} name="type" rules={[{ required: true }]}>
            <Select
              options={[
                { value: 'wecom', label: t('企业微信机器人') },
                { value: 'dingtalk', label: t('钉钉机器人') },
                { value: 'feishu', label: t('飞书机器人') },
                { value: 'generic', label: t('通用 webhook') },
              ]}
            />
          </Form.Item>
          <Form.Item label={t('名称')} name="name" rules={[{ required: true, message: '名称必填' }]}>
            <Input placeholder={t('如：运维群机器人')} />
          </Form.Item>
          <Form.Item
            label={t('Webhook 地址')}
            name="webhook"
            rules={[{ required: true, message: t('webhook 必填') }, { pattern: /^https?:\/\//, message: t('必须是 http(s) 地址') }]}
          >
            <Input placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..." />
          </Form.Item>
          <Form.Item label={t('启用')} name="enabled" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}

/** Tab 3：邮箱告警（SMTP） */
function EmailPanel() {
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    http
      .get<never, Record<string, unknown>>('/settings/notify-email')
      .then((d) =>
        form.setFieldsValue({
          ...d,
          password: '',
          to_addrs: Array.isArray(d.to_addrs) ? (d.to_addrs as string[]).join(',') : '',
        }),
      )
      .catch(() => {});
  }, [form]);

  const save = async () => {
    const v = await form.validateFields();
    const body: Record<string, unknown> = { ...v, to_addrs: (v.to_addrs as string).split(',').map((s) => s.trim()).filter(Boolean) };
    if (!v.password) delete body.password; // 留空 = 不修改
    setLoading(true);
    try {
      await http.put('/settings/notify-email', body);
      message.success(t('邮箱配置已保存'));
      form.setFieldValue('password', '');
    } catch {
      /* 拦截器已提示 */
    } finally {
      setLoading(false);
    }
  };

  return (
    <Form form={form} layout="vertical" style={{ maxWidth: 560 }} onFinish={save}>
      <Row gutter={12}>
        <Col span={8}>
          <Form.Item label={t('启用邮箱告警')} name="enabled" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Col>
        <Col span={16}>
          <Form.Item label={t('SMTP 服务器')} name="smtp_host">
            <Input placeholder="smtp.exmail.qq.com" />
          </Form.Item>
        </Col>
      </Row>
      <Row gutter={12}>
        <Col span={8}>
          <Form.Item label={t('端口')} name="smtp_port" initialValue={465}>
            <InputNumber style={{ width: '100%' }} min={1} max={65535} />
          </Form.Item>
        </Col>
        <Col span={8}>
          <Form.Item label="SSL" name="smtp_ssl" valuePropName="checked" initialValue={true}>
            <Switch />
          </Form.Item>
        </Col>
        <Col span={8}>
          <Form.Item label={t('发件人')} name="from_addr">
            <Input placeholder="alert@company.com" />
          </Form.Item>
        </Col>
      </Row>
      <Form.Item label={t('认证用户名')} name="username">
        <Input />
      </Form.Item>
      <Form.Item label={t('认证密码')} name="password" extra={t('留空 = 保持已保存的密码不变')}>
        <Input.Password placeholder="••••••" autoComplete="new-password" />
      </Form.Item>
      <Form.Item label={t('收件人（逗号分隔）')} name="to_addrs">
        <Input placeholder="ops@company.com, it@company.com" />
      </Form.Item>
      <Button type="primary" htmlType="submit" loading={loading}>
        保存邮箱配置
      </Button>
    </Form>
  );
}

/** Tab 4：会话策略（空闲自动断开 + 免扫码时长） */
function SessionPolicyPanel() {
  const { modal } = App.useApp();
  const [idleMin, setIdleMin] = useState<number | null>(null);
  const [ignoreUsers, setIgnoreUsers] = useState('');
  const [tokenMin, setTokenMin] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [applying, setApplying] = useState(false);

  const load = () => {
    http
      .get<never, { idle_timeout_minutes: number; idle_ignore_users: string; auth_token_lifetime_minutes: number }>(
        '/settings/session',
      )
      .then((d) => {
        setIdleMin(d.idle_timeout_minutes);
        setIgnoreUsers(d.idle_ignore_users ?? '');
        setTokenMin(d.auth_token_lifetime_minutes);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  };
  useEffect(load, []);

  const save = async () => {
    setSaving(true);
    try {
      await http.put('/settings/session', {
        idle_timeout_minutes: idleMin ?? 0,
        idle_ignore_users: ignoreUsers,
        auth_token_lifetime_minutes: tokenMin ?? 1440,
      });
      message.success(t('会话策略已保存（空闲断开 15 秒内生效）'));
    } catch {
      /* 拦截器已提示 */
    } finally {
      setSaving(false);
    }
  };

  const applyToken = () => {
    modal.confirm({
      title: t('确认把免扫码时长下发到双节点？'),
      content:
        t('将修改双节点配置并重启接入服务（在线会话中断 15-30 秒后自动恢复）。新时长立即按验证时刻计算：已签发凭证若超新时长，下次重连即要求重新扫码。'),
      okText: t('确认下发'),
      onOk: async () => {
        setApplying(true);
        try {
          const out = await http.post<never, { lifetime_seconds: number; results: { node: string; ok: boolean }[] }>(
            '/settings/session/apply',
          );
          const okCount = out.results.filter((r) => r.ok).length;
          message.success(t('已下发双节点（{v0}/2 成功），免扫码时长 {v1} 分钟', { v0: okCount, v1: out.lifetime_seconds / 60 }));
          load();
        } catch {
          /* 拦截器已提示 */
        } finally {
          setApplying(false);
        }
      },
    });
  };

  return (
    <div style={{ maxWidth: 560 }}>
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message={t('空闲 = 会话流量零增长。超过阈值自动断开该用户连接；0 = 关闭自动断开（默认）')}
        description={t('免扫码时长 = 用户扫码一次后、多少时间内重连不再要求扫码（auth-token 有效期）。到期后必须重新扫码（含各 IM 渠道）。下限 60 分钟以保证会话内重协商兼容。')}
      />
      <Form layout="vertical">
        <Form.Item label={t('空闲自动断开（分钟）')} extra={t('例如 30 = 空闲 30 分钟自动断开；0 = 关闭')} required>
          <InputNumber
            style={{ width: 200 }}
            min={0}
            max={10080}
            value={idleMin ?? undefined}
            disabled={loading}
            onChange={(v) => setIdleMin(typeof v === 'number' ? v : 0)}
          />
        </Form.Item>
        <Form.Item label={t('忽略名单（逗号分隔，不参与空闲断开）')} extra={t('机器/服务通道等常驻连接，默认 ha-test-client')}>
          <Input
            value={ignoreUsers}
            disabled={loading}
            onChange={(e) => setIgnoreUsers(e.target.value)}
            placeholder="ha-test-client"
          />
        </Form.Item>
        <Form.Item
          label={t('免扫码时长（分钟）')}
          extra={t('当前 1440 = 扫码一次 24 小时内重连免扫码。改为 60 = 1 小时后必须重新扫码。保存后需点下方按钮下发才生效')}
          required
        >
          <InputNumber
            style={{ width: 200 }}
            min={60}
            max={10080}
            value={tokenMin ?? undefined}
            disabled={loading}
            onChange={(v) => setTokenMin(typeof v === 'number' ? v : 1440)}
          />
        </Form.Item>
        <Space wrap>
          <Button type="primary" loading={saving} disabled={loading} onClick={save}>
            保存策略
          </Button>
          <Button danger loading={applying} disabled={loading} onClick={applyToken}>
            下发免扫码时长到双节点（会短暂断线）
          </Button>
        </Space>
      </Form>
    </div>
  );
}

/** Tab 5：License（§17） */
interface LicenseState {
  status: 'trial' | 'ok' | 'expiring' | 'grace' | 'expired';
  edition: string;
  customer: string;
  lic_id?: string;
  used_users: number;
  max_users?: number;
  live_sessions: number;
  max_concurrent?: number;
  nodes: number;
  max_nodes?: number;
  features: string[];
  expires_at?: string | null;
  days_remaining?: number;
  trial_deadline?: string;
}

const STATUS_META: Record<LicenseState['status'], { color: string; text: string }> = {
  trial: { color: 'blue', text: t('试用模式') },
  ok: { color: 'green', text: t('授权有效') },
  expiring: { color: 'orange', text: t('即将到期') },
  grace: { color: 'red', text: t('已到期（宽限期）') },
  expired: { color: 'red', text: t('已过期（拒绝新认证）') },
};

function UsageBar({ used, max }: { used: number; max?: number }) {
  if (!max) return <Typography.Text type="secondary">{t('无授权约束')}</Typography.Text>;
  const pct = Math.min(100, Math.round((used / max) * 100));
  const color = pct > 90 ? '#cf1322' : pct > 75 ? '#faad14' : '#52c41a';
  return (
    <div>
      <div style={{ background: '#f0f0f0', borderRadius: 4, height: 10 }}>
        <div style={{ width: `${pct}%`, background: color, height: 10, borderRadius: 4 }} />
      </div>
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        {used} / {max}
      </Typography.Text>
    </div>
  );
}

function LicensePanel() {
  const [st, setSt] = useState<LicenseState | null>(null);
  const [licRaw, setLicRaw] = useState('');
  const [loading, setLoading] = useState(true);
  const [importing, setImporting] = useState(false);

  const load = () => {
    http
      .get<never, LicenseState>('/settings/license')
      .then(setSt)
      .catch(() => {})
      .finally(() => setLoading(false));
  };
  useEffect(load, []);

  const importLic = async () => {
    if (!licRaw.trim()) return message.warning(t('请粘贴 .lic 文件内容'));
    setImporting(true);
    try {
      const out = await http.post<never, LicenseState>('/settings/license', { raw: licRaw.trim() });
      message.success(t('授权已导入并生效（{v0} / {v1}）', { v0: out.edition, v1: out.customer }));
      setLicRaw('');
      setSt(out);
    } catch {
      /* 拦截器已提示 */
    } finally {
      setImporting(false);
    }
  };

  if (loading) return <Typography.Text type="secondary">{t('加载中…')}</Typography.Text>;
  if (!st) return <Typography.Text type="danger">{t('状态获取失败')}</Typography.Text>;
  const meta = STATUS_META[st.status] ?? STATUS_META.ok;

  return (
    <div style={{ maxWidth: 640 }}>
      <Alert
        type={st.status === 'expired' || st.status === 'grace' ? 'error' : st.status === 'expiring' ? 'warning' : 'info'}
        showIcon
        style={{ marginBottom: 16 }}
        message={
          <Space>
            <Tag color={meta.color}>{meta.text}</Tag>
            {st.status === 'trial' && st.trial_deadline ? (
              <span>试用截止 {st.trial_deadline}</span>
            ) : st.expires_at ? (
              <span>到期时间 {st.expires_at.slice(0, 10)}，剩余 {st.days_remaining} 天</span>
            ) : (
              <span>{t('永久授权')}</span>
            )}
          </Space>
        }
        description={
          st.status === 'expired'
            ? t('授权已过宽限期：新用户/新连接将被拒绝，已建立隧道保留至自然断开。请导入新授权文件。')
            : st.status === 'grace'
              ? t('授权已到期，宽限期内功能全可用，请尽快续费。')
              : t('私有化离线授权：Ed25519 签名验证，导入即生效，无需重启。')
        }
      />
      <Row gutter={[16, 12]}>
        <Col span={12}>
          <Statistic title={t('版本')} value={st.edition} />
        </Col>
        <Col span={12}>
          <Statistic title={t('客户')} value={st.customer} />
        </Col>
        <Col span={8}>
          <Statistic title={t('启用用户')} value={st.used_users} suffix={st.max_users ? `/ ${st.max_users}` : ''} />
          <div style={{ marginTop: 6 }}>
            <UsageBar used={st.used_users} max={st.max_users} />
          </div>
        </Col>
        <Col span={8}>
          <Statistic title={t('在线会话')} value={st.live_sessions} suffix={st.max_concurrent ? `/ ${st.max_concurrent}` : ''} />
          <div style={{ marginTop: 6 }}>
            <UsageBar used={st.live_sessions} max={st.max_concurrent} />
          </div>
        </Col>
        <Col span={8}>
          <Statistic title={t('节点')} value={st.nodes} suffix={st.max_nodes ? `/ ${st.max_nodes}` : ''} />
        </Col>
      </Row>
      {st.features?.length > 0 && (
        <div style={{ margin: '16px 0' }}>
          <Typography.Text type="secondary">{t('功能模块：')}</Typography.Text>
          {st.features.map((f) => (
            <Tag key={f} style={{ marginLeft: 4 }}>
              {f}
            </Tag>
          ))}
        </div>
      )}
      <Alert
        type="info"
        showIcon
        style={{ margin: '8px 0 12px' }}
        message={t('粘贴厂商签发的 .lic 文件内容（一行：base64(payload).base64(signature)），导入即验签生效，无需重启')}
      />
      <Input.TextArea
        rows={4}
        value={licRaw}
        onChange={(e) => setLicRaw(e.target.value)}
        placeholder="base64(payload).base64(signature)"
      />
      <Button type="primary" style={{ marginTop: 12 }} loading={importing} onClick={importLic}>
        导入授权
      </Button>
    </div>
  );
}

/** Tab 5：加密套件（标准 / 国密切换） */
interface CryptoState {
  suite: 'standard' | 'gm';
  label: string;
  data_ciphers: string;
  auth: string;
}

function CryptoPanel() {
  const { modal } = App.useApp();
  const [st, setSt] = useState<CryptoState | null>(null);
  const [applying, setApplying] = useState(false);

  const load = () => {
    http
      .get<never, CryptoState>('/settings/crypto')
      .then(setSt)
      .catch(() => {});
  };
  useEffect(load, []);

  const apply = (suite: 'standard' | 'gm') => {
    const target = suite === 'gm' ? t('国密套件（SM4-GCM / SM3）') : t('标准套件（AES-256-GCM / SHA256）');
    modal.confirm({
      title: t('确认切换到{v0}？', { v0: target }),
      content:
        t('将改写双节点配置并重启接入服务（在线会话中断 15-30 秒后自动恢复）；') +
        t('已有客户端配置不会自动更新——切换后用户必须重新下载 .ovpn 才能继续连接（新模板跟随新套件）。') +
        t('切换全程通常 30 秒内完成，失败时节点保持原套件运行。'),
      okText: t('确认切换'),
      onOk: async () => {
        setApplying(true);
        try {
          await http.put('/settings/crypto', { suite });
          message.success(t('已切换到{v0}（双节点已重启）', { v0: target }));
          load();
        } catch {
          /* 拦截器已提示 */
        } finally {
          setApplying(false);
        }
      },
    });
  };

  const isGm = st?.suite === 'gm';
  return (
    <div style={{ maxWidth: 620 }}>
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message={t('数据通道加密套件：标准（AES-256-GCM / SHA256）或 国密（SM4-GCM / SM3）')}
        description={
          t('切换作用于双节点与新生成的客户端配置模板；控制通道 TLS 套件保持标准（官方 Windows 客户端不含 TLS 国密套件）。') +
          t('切回标准套件同样需要用户重新下载配置。')
        }
      />
      <Form layout="vertical">
        <Form.Item label={t('当前生效')} extra={st ? `数据通道：${st.data_ciphers} · 认证摘要：${st.auth}` : '加载中'}>
          <Tag color={isGm ? 'gold' : 'green'}>{st?.label ?? '…'}</Tag>
        </Form.Item>
        <Space wrap>
          <Button type="primary" loading={applying} disabled={applying || !st} onClick={() => apply(isGm ? 'standard' : 'gm')}>
            {isGm ? t('切回标准套件（AES/SHA256）') : t('切换为国密套件（SM4/SM3）')}
          </Button>
        </Space>
      </Form>
    </div>
  );
}

/** Tab 6：接入安全（证书与身份绑定开关） */
interface CertBindingState {
  binding: 'off' | 'strict';
  label: string;
}

function CertBindingPanel() {
  const { modal, message } = App.useApp();
  const [st, setSt] = useState<CertBindingState | null>(null);
  const [applying, setApplying] = useState(false);

  const load = () => {
    http
      .get<never, CertBindingState>('/settings/cert-binding')
      .then(setSt)
      .catch(() => {});
  };
  useEffect(load, []);

  const apply = (binding: 'off' | 'strict') => {
    const toStrict = binding === 'strict';
    modal.confirm({
      title: toStrict ? t('开启「证书与身份绑定」？') : t('关闭「证书与身份绑定」？'),
      content: toStrict
        ? t('开启后：① 客户端证书必须真实有效（服务端启用证书校验与吊销检查）；') +
          t('② 扫码登录的人必须就是该配置文件所属的用户——他人拿到别人的 .ovpn 文件用自己的账号扫码将被拒绝；') +
          t('③ 吊销设备立即在 TLS 层作废其配置文件。') +
          t('切换将重启双节点接入与认证服务（约 4 秒中断，在线会话自动重连）；已建立的老证书不受影响（按设备列表校验，与用户名无关）。')
        : t('关闭后回到宽松模式：证书仅作准入凭据，扫码者与证书属主可为不同人；吊销设备不再有 TLS 层阻断。切换将重启双节点服务（约 4 秒中断）。'),
      okText: toStrict ? t('确认开启') : t('确认关闭'),
      onOk: async () => {
        setApplying(true);
        try {
          const res = await http.put<never, { notice: string }>('/settings/cert-binding', {
            binding,
            confirm_impact: true,
          });
          message.success(res.notice || t('已切换'));
          load();
        } catch {
          /* 拦截器已提示 */
        } finally {
          setApplying(false);
        }
      },
    });
  };

  const isStrict = st?.binding === 'strict';
  return (
    <div style={{ maxWidth: 620 }}>
      <Alert
        type={isStrict ? 'success' : 'warning'}
        showIcon
        style={{ marginBottom: 16 }}
        message={t('证书与扫码人一致性：防止配置文件外借/外泄后被他人账号使用')}
        description={
          t('宽松（默认）：.ovpn 文件仅是准入凭据，任何有效账号扫码都能用它接入（进入的是扫码者自己的身份与权限）。') +
          t('严格：文件所属人 = 扫码人，且吊销设备即时作废文件。两种模式下扫码认证都不可跳过。')
        }
      />
      <Form layout="vertical">
        <Form.Item label={t('当前生效')}>
          <Tag color={isStrict ? 'green' : 'orange'}>{st?.label ?? '…'}</Tag>
        </Form.Item>
        <Space wrap>
          <Button
            type={isStrict ? 'default' : 'primary'}
            danger={isStrict}
            loading={applying}
            disabled={applying || !st}
            onClick={() => apply(isStrict ? 'off' : 'strict')}
          >
            {isStrict ? t('关闭绑定（恢复宽松）') : t('开启严格绑定')}
          </Button>
        </Space>
      </Form>
    </div>
  );
}

/** Tab 8：IPv6 隧道开关（#80） */
interface IPv6State {
  enabled: boolean;
  label: string;
}

function IPv6Panel() {
  const { modal, message } = App.useApp();
  const [st, setSt] = useState<IPv6State | null>(null);
  const [applying, setApplying] = useState(false);

  const load = () => {
    http
      .get<never, IPv6State>('/settings/ipv6')
      .then(setSt)
      .catch(() => {});
  };
  useEffect(load, []);

  const apply = (enabled: boolean) => {
    modal.confirm({
      title: enabled ? '开启 IPv6 隧道？' : '关闭 IPv6 隧道？',
      content: enabled
        ? '开启后：客户端重连时将同时获得 IPv6 隧道地址（fdaa:2026:192::/48 段），仅可访问已授权的 IPv6 资源。' +
          '将改写双节点配置并重启接入服务（在线会话中断 15-30 秒后自动恢复）。'
        : '关闭后：客户端仅使用 IPv4，不再分配 IPv6 隧道地址。将改写双节点配置并重启接入服务（在线会话中断 15-30 秒后自动恢复）。',
      okText: enabled ? '确认开启' : '确认关闭',
      onOk: async () => {
        setApplying(true);
        try {
          const res = await http.put<never, { notice: string }>('/settings/ipv6', {
            enabled,
            confirm_impact: true,
          });
          message.success(res.notice || '已切换');
          load();
        } catch {
          /* 拦截器已提示 */
        } finally {
          setApplying(false);
        }
      },
    });
  };

  const on = st?.enabled === true;
  return (
    <div style={{ maxWidth: 620 }}>
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message={t('IPv6 隧道：客户端是否同时分配 IPv6 地址')}
        description={
          '默认关闭（仅 IPv4）。开启为实验性能力：需要 IPv6 资源访问或 IPv6 连通性测试时再开启。' +
          '无论开关状态，客户端访问内网资源均受路由白名单管控（IPv4 与 IPv6 各自独立生效）。'
        }
      />
      <Form layout="vertical">
        <Form.Item label={t('当前生效')}>
          <Tag color={on ? 'green' : 'default'}>{st?.label ?? '…'}</Tag>
        </Form.Item>
        <Space wrap>
          <Button
            type={on ? 'default' : 'primary'}
            loading={applying}
            disabled={applying || !st}
            onClick={() => apply(!on)}
          >
            {on ? '关闭 IPv6 隧道' : '开启 IPv6 隧道'}
          </Button>
        </Space>
      </Form>
    </div>
  );
}

/** Tab：管理员账号（P0-3，仅 super_admin 可见可管；后端同角色门禁） */
interface AdminItem {
  id: number;
  username: string;
  roles: string[];
  must_change_password: boolean;
  created_at: string;
}
const ROLE_OPTIONS = [
  { value: 'super_admin', label: 'super_admin（超级管理员）' },
  { value: 'security_admin', label: 'security_admin（安全管理员）' },
  { value: 'auditor', label: 'auditor（审计员，只读）' },
];

function AdminsPanel() {
  const { message } = App.useApp();
  const [list, setList] = useState<AdminItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [editing, setEditing] = useState<AdminItem | null>(null);
  const [resetting, setResetting] = useState<AdminItem | null>(null);
  const [createForm] = Form.useForm();
  const [editForm] = Form.useForm();
  const [resetForm] = Form.useForm();

  const load = () => {
    setLoading(true);
    http
      .get<never, { list: AdminItem[] }>('/admins')
      .then((d) => setList(d.list || []))
      .finally(() => setLoading(false));
  };
  useEffect(load, []);

  return (
    <>
      <div style={{ marginBottom: 12 }}>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
          {t('新建管理员')}
        </Button>
        <span style={{ marginLeft: 12, color: '#888', fontSize: 13 }}>
          {t('三权分立：super_admin 管系统/账号，security_admin 管策略，auditor 只读审计')}
        </span>
      </div>
      <Table<AdminItem>
        rowKey="id"
        loading={loading}
        dataSource={list}
        pagination={false}
        columns={[
          { title: t('用户名'), dataIndex: 'username' },
          {
            title: t('角色'),
            dataIndex: 'roles',
            render: (roles: string[]) => roles.map((r) => <Tag key={r} color={r === 'super_admin' ? 'blue' : r === 'auditor' ? 'green' : 'orange'}>{r}</Tag>),
          },
          {
            title: t('下次登录改密'),
            dataIndex: 'must_change_password',
            render: (v: boolean) => (v ? <Tag color="red">{t('是')}</Tag> : t('否')),
          },
          { title: t('创建时间'), dataIndex: 'created_at' },
          {
            title: t('操作'),
            render: (_, record) => (
              <Space>
                <a
                  onClick={() => {
                    setEditing(record);
                    editForm.setFieldsValue({ roles: record.roles });
                  }}
                >
                  {t('改角色')}
                </a>
                <a onClick={() => { setResetting(record); resetForm.resetFields(); }}>{t('重置密码')}</a>
                <Popconfirm
                  title={t('确认删除该管理员？')}
                  onConfirm={() =>
                    http.delete(`/admins/${record.id}`).then(() => {
                      message.success(t('已删除'));
                      load();
                    })
                  }
                >
                  <a style={{ color: '#d70015' }}>{t('删除')}</a>
                </Popconfirm>
              </Space>
            ),
          },
        ]}
      />

      <Modal
        title={t('新建管理员')}
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onOk={() =>
          createForm.validateFields().then((v) =>
            http
              .post('/admins', v)
              .then(() => {
                message.success(t('已创建，该账号首次登录需改密'));
                setCreateOpen(false);
                createForm.resetFields();
                load();
              })
          )
        }
      >
        <Form form={createForm} layout="vertical">
          <Form.Item name="username" label={t('用户名')} rules={[{ required: true, max: 64 }]}>
            <Input />
          </Form.Item>
          <Form.Item name="password" label={t('初始密码')} rules={[{ required: true, min: 8, max: 72 }]}>
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item name="roles" label={t('角色')} rules={[{ required: true }]}>
            <Select mode="multiple" options={ROLE_OPTIONS} />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={t('修改角色') + `：${editing?.username ?? ''}`}
        open={!!editing}
        onCancel={() => setEditing(null)}
        onOk={() =>
          editForm.validateFields().then((v) =>
            http.put(`/admins/${editing!.id}`, v).then(() => {
              message.success(t('已更新'));
              setEditing(null);
              load();
            })
          )
        }
      >
        <Form form={editForm} layout="vertical">
          <Form.Item name="roles" label={t('角色')} rules={[{ required: true }]}>
            <Select mode="multiple" options={ROLE_OPTIONS} />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={t('重置密码') + `：${resetting?.username ?? ''}`}
        open={!!resetting}
        onCancel={() => setResetting(null)}
        onOk={() =>
          resetForm.validateFields().then((v) =>
            http.post(`/admins/${resetting!.id}/password`, v).then(() => {
              message.success(t('已重置，该账号下次登录需改密'));
              setResetting(null);
              load();
            })
          )
        }
      >
        <Form form={resetForm} layout="vertical">
          <Form.Item name="password" label={t('新密码')} rules={[{ required: true, min: 8, max: 72 }]}>
            <Input.Password autoComplete="new-password" />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}

/** 绑定二维码：otpauth URI 直接给验证器 App 扫（部分设备不便手动录入密钥） */
function TotpQr({ uri }: { uri: string }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    if (ref.current) QRCode.toCanvas(ref.current, uri, { width: 168, margin: 1 }).catch(() => {});
  }, [uri]);
  return <canvas ref={ref} style={{ display: 'block', margin: '12px 0' }} />;
}

/** TOTP 双因素绑定卡（P1-e/#109）：系统级强制开关（super_admin）+ 个人绑定/解绑 */
function TotpPanel() {
  const { message } = App.useApp();
  const me = useAuthStore((s) => s.user);
  const isSuper = !!me?.roles?.includes('super_admin');
  const [state, setState] = useState<{ secret: string; otpauth_uri: string; enabled: boolean } | null>(null);
  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [showQr, setShowQr] = useState(false);
  const [enforced, setEnforced] = useState<boolean | null>(null);
  const [userPolicy, setUserPolicy] = useState<string | null>(null);

  const load = () => {
    http.get<never, { secret: string; otpauth_uri: string; enabled: boolean }>('/auth/totp/setup').then(setState);
    if (isSuper) {
      http.get<never, { enforced: boolean }>('/settings/totp').then((d) => setEnforced(d.enforced)).catch(() => {});
      http.get<never, { policy: string }>('/settings/user-totp').then((d) => setUserPolicy(d.policy)).catch(() => {});
    }
  };
  useEffect(load, [isSuper]);

  const toggleEnforced = (v: boolean) => {
    http
      .put('/settings/totp', { enforced: v })
      .then(() => {
        setEnforced(v);
        message.success(v ? t('已开启系统级强制：所有管理员登录必须绑定双因素') : t('已关闭系统级强制'));
      })
      .catch(() => load());
  };

  const changeUserPolicy = (v: string) => {
    http
      .put('/settings/user-totp', { policy: v })
      .then(() => {
        setUserPolicy(v);
        message.success(t('用户双因素策略已更新'));
      })
      .catch(() => load());
  };

  const bind = () => {
    setLoading(true);
    http
      .post('/auth/totp/enable', { code })
      .then(() => {
        message.success(t('双因素已启用，下次登录需输入动态验证码'));
        setCode('');
        setShowQr(false);
        load();
      })
      .finally(() => setLoading(false));
  };
  const unbind = () => {
    setLoading(true);
    http
      .post('/auth/totp/disable', { code })
      .then(() => {
        message.success(t('双因素已关闭'));
        setCode('');
        load();
      })
      .finally(() => setLoading(false));
  };

  return (
    <div style={{ maxWidth: 560 }}>
      {isSuper && enforced !== null && (
        <Card size="small" style={{ marginBottom: 16, background: '#EFF6FF', border: '1px solid #BFDBFE' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={{ fontWeight: 600 }}>{t('系统级强制双因素')}</div>
              <div style={{ fontSize: 12, color: '#6e6e73' }}>{t('开启后所有管理员登录必须绑定双因素；未绑定者登录时仅可完成绑定')}</div>
            </div>
            <Switch checked={enforced} onChange={toggleEnforced} />
          </div>
        </Card>
      )}
      {isSuper && userPolicy !== null && (
        <Card size="small" style={{ marginBottom: 16, background: '#EFF6FF', border: '1px solid #BFDBFE' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
            <div>
              <div style={{ fontWeight: 600 }}>{t('用户双因素策略')}</div>
              <div style={{ fontSize: 12, color: '#6e6e73' }}>
                {t('门户用户登录策略：命中者未绑定时登录仅可完成绑定，绑定后恢复正常使用。')}
              </div>
            </div>
            <Select
              style={{ width: 150, flex: 'none' }}
              value={userPolicy}
              onChange={changeUserPolicy}
              options={[
                { value: 'off', label: t('关闭') },
                { value: 'local_only', label: t('仅本地账号') },
                { value: 'all', label: t('全员强制') },
              ]}
            />
          </div>
        </Card>
      )}
      <Alert
        type={state?.enabled ? 'success' : 'info'}
        showIcon
        message={state?.enabled ? t('双因素认证已启用') : t('双因素认证未启用')}
        description={t('启用后，管理台登录在账号密码之外还需输入验证器 App 的 6 位动态码（Google Authenticator 等兼容）。')}
        style={{ marginBottom: 16 }}
      />
      {!state?.enabled && (
        <div style={{ marginBottom: 12 }}>
          <Button onClick={() => setShowQr(true)}>{t('获取绑定密钥')}</Button>
          {showQr && state && (
            <>
              <TotpQr uri={state.otpauth_uri} />
              <Typography.Text type="secondary" style={{ display: 'block', marginBottom: 8 }}>
                {t('用验证器 App 扫描上方二维码（不便扫码时复制完整 URI 或「手动输入密钥」录入 secret），然后输入 App 显示的 6 位码完成绑定：')}
              </Typography.Text>
              <Typography.Paragraph copyable={{ text: state.otpauth_uri }} style={{ wordBreak: 'break-all', fontSize: 12, marginTop: 0 }}>
                {state.otpauth_uri}
              </Typography.Paragraph>
            </>
          )}
        </div>
      )}
      <Space>
        <Input
          style={{ width: 160 }}
          placeholder={t('6 位动态验证码')}
          maxLength={6}
          inputMode="numeric"
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
        />
        {state?.enabled ? (
          enforced ? (
            <Button danger disabled title={t('系统已强制双因素，无法自行关闭')}>{t('系统强制中，不可关闭')}</Button>
          ) : (
            <Popconfirm title={t('确认关闭双因素？')} onConfirm={unbind}>
              <Button danger loading={loading}>{t('关闭双因素')}</Button>
            </Popconfirm>
          )
        ) : (
          <Button type="primary" loading={loading} disabled={!showQr || code.length !== 6} onClick={bind}>
            {t('验证并启用')}
          </Button>
        )}
      </Space>
    </div>
  );
}

export default function Settings() {
  return (
    <PageContainer title={t('系统设置')} subTitle={t('品牌/客户端接入/告警通知/会话策略/加密套件/接入安全/管理员/License')}>
      <Card>
        <Tabs
          items={[
            { key: 'branding', label: t('品牌与接入'), children: <BrandingPanel /> },
            { key: 'channels', label: t('通知渠道'), children: <ChannelsPanel /> },
            { key: 'email', label: t('邮箱告警'), children: <EmailPanel /> },
            { key: 'session', label: t('会话策略'), children: <SessionPolicyPanel /> },
            { key: 'crypto', label: t('加密套件'), children: <CryptoPanel /> },
            { key: 'certbinding', label: t('接入安全'), children: <CertBindingPanel /> },
            { key: 'admins', label: t('管理员账号'), children: <AdminsPanel /> },
            { key: 'totp', label: t('双因素认证'), children: <TotpPanel /> },
            { key: 'ipv6', label: 'IPv6', children: <IPv6Panel /> },
            { key: 'license', label: 'License', children: <LicensePanel /> },
          ]}
        />
      </Card>
    </PageContainer>
  );
}
