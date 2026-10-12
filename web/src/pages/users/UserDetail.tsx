import { PageContainer } from '@ant-design/pro-components';
import { t } from '../../i18n';
import { App, Button, Descriptions, Card, Form, Input, Modal, Tabs, Table, Statistic, Row, Col, Tag, Popconfirm, Space } from 'antd';

interface DeviceRow {
  id: number;
  device_name: string;
  cert_cn: string;
  platform: string;
  fingerprint: string;
  status: string;
  created_at: string;
}
import { useParams } from 'react-router-dom';
import { useEffect, useState } from 'react';
import http, { type PageData } from '../../api/client';
import type { User } from '../../api/types';
import { formatBytes } from '../../utils/format';

interface SessionRow {
  connected_at: string;
  trusted_ip: string;
  virtual_ip: string;
  bytes_in: number;
  bytes_out: number;
  duration: number;
}

interface Traffic {
  total_bytes_in: number;
  total_bytes_out: number;
  session_count: number;
  daily: { day: string; bytes_in: number; bytes_out: number }[];
}

// 随机密码：大小写/数字/安全符号各保证至少 1 位，共 12 位
// （字符集剔除易混淆的 I l O 0 1；符号避开 shell 常见展开字符 `$` 与反引号；
// 用 crypto.getRandomValues——Math.random 可预测，不用于任何凭据生成）
const genPassword = () => {
  const groups = ['ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnpqrstuvwxyz', '23456789', '!@#%^&*_-'];
  const all = groups.join('');
  const pick = (s: string) => {
    const b = new Uint32Array(1);
    crypto.getRandomValues(b);
    return s[b[0] % s.length];
  };
  let out = groups.map(pick).join('');
  while (out.length < 12) out += pick(all);
  return out;
};

export default function UserDetail() {
  const { id } = useParams();
  const { message } = App.useApp();
  const [user, setUser] = useState<User | null>(null);
  const [sessions, setSessions] = useState<SessionRow[]>([]);
  const [traffic, setTraffic] = useState<Traffic | null>(null);
  const [devices, setDevices] = useState<DeviceRow[]>([]);
  const [pwOpen, setPwOpen] = useState(false);
  const [pwSaving, setPwSaving] = useState(false);
  const [pwForm] = Form.useForm();

  const loadDevices = () => {
    if (!id) return;
    http.get<never, PageData<DeviceRow>>(`/users/${id}/devices`)
      .then((d) => setDevices(d.list)).catch(() => {});
  };

  useEffect(() => {
    if (!id) return;
    http.get<never, User>(`/users/${id}`).then(setUser).catch(() => {});
    http.get<never, PageData<SessionRow>>(`/users/${id}/sessions`)
      .then((d) => setSessions(d.list)).catch(() => {});
    http.get<never, Traffic>(`/users/${id}/traffic`).then(setTraffic).catch(() => {});
    loadDevices();
  }, [id]);

  const openReset = () => {
    pwForm.resetFields();
    pwForm.setFieldsValue({ password: genPassword() });
    setPwOpen(true);
  };

  const submitReset = async () => {
    const v = await pwForm.validateFields();
    setPwSaving(true);
    try {
      await http.put(`/users/${id}/password`, { password: v.password });
      message.success(t('密码已重置，请将新密码告知用户'));
      setPwOpen(false);
    } catch {
      /* 拦截器已提示 */
    } finally {
      setPwSaving(false);
    }
  };

  const submitTotpReset = async () => {
    try {
      await http.post(`/users/${id}/totp-reset`);
      message.success(t('双因素已重置，该用户下次门户登录将按策略重新绑定'));
      http.get<never, User>(`/users/${id}`).then(setUser).catch(() => {});
    } catch {
      /* 拦截器已提示 */
    }
  };

  const sessionCols = [
    { title: t('时间'), dataIndex: 'connected_at' },
    { title: t('来源 IP'), dataIndex: 'trusted_ip' },
    { title: t('虚拟 IP'), dataIndex: 'virtual_ip' },
    { title: t('上传'), dataIndex: 'bytes_in', render: (v: number) => formatBytes(v) },
    { title: t('下载'), dataIndex: 'bytes_out', render: (v: number) => formatBytes(v) },
    { title: t('时长(秒)'), dataIndex: 'duration' },
  ];

  return (
    <PageContainer title={t('用户详情')} subTitle={`ID: ${id}`} onBack={() => window.history.back()}>
      <Card
        style={{ marginBottom: 16 }}
        extra={
          <Space>
            {user?.source === 'local' && (
              <Button type="primary" onClick={openReset}>
                重置密码
              </Button>
            )}
            {!!user?.totp_enabled && (
              <Popconfirm
                title={t('确认重置双因素？')}
                description={t('重置后该用户需重新绑定验证器（丢验证器恢复通道）。')}
                onConfirm={submitTotpReset}
              >
                <Button danger>重置双因素</Button>
              </Popconfirm>
            )}
          </Space>
        }
      >
        <Descriptions column={3}>
          <Descriptions.Item label={t('用户名')}>{user?.username ?? '-'}</Descriptions.Item>
          <Descriptions.Item label={t('姓名')}>{user?.display_name ?? '-'}</Descriptions.Item>
          <Descriptions.Item label={t('认证来源')}>{user?.source ?? '-'}</Descriptions.Item>
          <Descriptions.Item label={t('状态')}>{user?.status ?? '-'}</Descriptions.Item>
          <Descriptions.Item label={t('设备配额')}>{user?.device_quota ?? '-'}</Descriptions.Item>
          <Descriptions.Item label={t('双因素认证')}>{user?.totp_enabled ? t('已绑定') : t('未绑定')}</Descriptions.Item>
          <Descriptions.Item label={t('创建时间')}>{user?.created_at ?? '-'}</Descriptions.Item>
        </Descriptions>
      </Card>
      <Modal
        title={t('重置本地账号密码')}
        open={pwOpen}
        onOk={submitReset}
        onCancel={() => setPwOpen(false)}
        confirmLoading={pwSaving}
        okText={t('确认重置')}
        cancelText={t('取消')}
        destroyOnHidden
      >
        <Form form={pwForm} layout="vertical">
          <Form.Item
            name="password"
            label={t('新密码')}
            rules={[
              { required: true, message: t('请输入新密码') },
              { min: 8, message: t('密码长度不能少于 8 位') },
            ]}
            extra={
              <a onClick={() => pwForm.setFieldsValue({ password: genPassword() })}>{t('随机生成')}</a>
            }
          >
            <Input.Password autoComplete="new-password" maxLength={64} placeholder={t('至少 8 位')} />
          </Form.Item>
          <Form.Item
            name="confirm"
            label={t('确认新密码')}
            dependencies={['password']}
            rules={[
              { required: true, message: t('请再次输入新密码') },
              ({ getFieldValue }) => ({
                validator(_, value) {
                  if (!value || getFieldValue('password') === value) return Promise.resolve();
                  return Promise.reject(new Error(t('两次输入的密码不一致')));
                },
              }),
            ]}
          >
            <Input.Password autoComplete="new-password" maxLength={64} />
          </Form.Item>
        </Form>
      </Modal>
      <Card>
        <Tabs
          items={[
            {
              key: 'sessions',
              label: `历史会话${sessions.length ? ` (${sessions.length})` : ''}`,
              children: (
                <Table<SessionRow>
                  rowKey={(r) => r.connected_at + r.trusted_ip}
                  columns={sessionCols}
                  dataSource={sessions}
                  pagination={{ pageSize: 10 }}
                  size="small"
                />
              ),
            },
            {
              key: 'traffic',
              label: t('流量统计'),
              children: traffic ? (
                <>
                  <Row gutter={16} style={{ marginBottom: 16 }}>
                    <Col span={8}><Statistic title={t('累计上传')} value={formatBytes(traffic.total_bytes_in)} /></Col>
                    <Col span={8}><Statistic title={t('累计下载')} value={formatBytes(traffic.total_bytes_out)} /></Col>
                    <Col span={8}><Statistic title={t('会话次数')} value={traffic.session_count} /></Col>
                  </Row>
                  <Table
                    rowKey="day"
                    columns={[
                      { title: t('日期'), dataIndex: 'day' },
                      { title: t('上传'), dataIndex: 'bytes_in', render: (v: number) => formatBytes(v) },
                      { title: t('下载'), dataIndex: 'bytes_out', render: (v: number) => formatBytes(v) },
                    ]}
                    dataSource={traffic.daily}
                    pagination={false}
                    size="small"
                  />
                </>
              ) : null,
            },
            {
              key: 'devices',
              label: `设备列表${devices.length ? ` (${devices.length})` : ''}`,
              children: (
                <Table<DeviceRow>
                  rowKey="id"
                  columns={[
                    { title: t('设备名'), dataIndex: 'device_name' },
                    { title: t('证书 CN'), dataIndex: 'cert_cn' },
                    { title: t('平台'), dataIndex: 'platform' },
                    { title: t('状态'), dataIndex: 'status', render: (v: string) =>
                        v === 'active' ? <Tag color="green">{t('正常')}</Tag> : <Tag color="red">{t('已吊销')}</Tag> },
                    { title: t('创建时间'), dataIndex: 'created_at' },
                    {
                      title: t('操作'),
                      render: (_, r) =>
                        r.status === 'active' ? (
                          <a
                            style={{ color: '#cf1322' }}
                            onClick={() => {
                              http.post(`/devices/${r.id}/revoke`).then(() => loadDevices()).catch(() => {});
                            }}
                          >
                            吊销
                          </a>
                        ) : null,
                    },
                  ]}
                  dataSource={devices}
                  pagination={{ pageSize: 10 }}
                  size="small"
                />
              ),
            },
            {
              key: 'groups',
              label: t('所属组'),
              children: (
                <Table
                  rowKey="id"
                  columns={[{ title: 'ID', dataIndex: 'id', width: 80 }, { title: t('组名'), dataIndex: 'name' }]}
                  dataSource={user?.groups ?? []}
                  pagination={false}
                  size="small"
                  locale={{ emptyText: t('（无）') }}
                />
              ),
            },
          ]}
        />
      </Card>
    </PageContainer>
  );
}
