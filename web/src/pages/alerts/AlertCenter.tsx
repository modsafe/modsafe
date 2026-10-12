import { PageContainer } from '@ant-design/pro-components';
import { t } from '../../i18n';
import { ProTable, type ProColumns } from '@ant-design/pro-components';
import { App, Badge, Button, Modal, Popconfirm, Space, Switch, Tag } from 'antd';
import { useEffect, useState } from 'react';
import http from '../../api/client';

interface AlertRule {
  id: string;
  level: string;
  description: string;
  enabled: boolean;
  cooldown_minutes: number;
}
interface ActiveAlert {
  dedup_key: string;
  rule_id: string;
  level: string;
  fired_at: string;
  last_notified_at: string;
  detail: string;
}
interface HistoryAlert {
  rule_id: string;
  dedup_key: string;
  level: string;
  event: string;
  detail: string;
  notified_channels: string;
  event_time: string;
}

const LEVEL_COLOR: Record<string, string> = { critical: 'red', warn: 'orange', info: 'blue' };
const EVENT_TEXT: Record<string, string> = { fired: t('触发'), renotified: t('重提醒'), resolved: t('已恢复'), muted: t('静默') };

export default function AlertCenter() {
  const { message } = App.useApp();
  const [rules, setRules] = useState<AlertRule[]>([]);
  const [active, setActive] = useState<ActiveAlert[]>([]);
  const [maintUntil, setMaintUntil] = useState('');

  const load = () => {
    http.get<never, AlertRule[]>('/alerts/rules').then(setRules).catch(() => {});
    http.get<never, ActiveAlert[]>('/alerts/active').then(setActive).catch(() => {});
  };
  useEffect(() => {
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, []);

  const toggleRule = async (id: string, enabled: boolean) => {
    await http.put(`/alerts/rules/${id}`, { enabled });
    message.success(`规则 ${id} 已${enabled ? t('启用') : t('禁用')}`);
    load();
  };

  const setMaintenance = (hours: number) => {
    Modal.confirm({
      title: t('开启维护模式 {v0} 小时？', { v0: hours }),
      content: t('期间所有告警只记历史不外发（升级/变更窗口用）。'),
      onOk: async () => {
        const d = await http.post<never, { until: string }>('/alerts/maintenance', { hours });
        setMaintUntil(d.until);
        message.success(t('维护模式已开启，至 {v0}', { v0: d.until }));
      },
    });
  };

  const cancelMaintenance = async () => {
    await http.delete('/alerts/maintenance');
    setMaintUntil('');
    message.success(t('维护模式已取消'));
  };

  const ruleColumns: ProColumns<AlertRule>[] = [
    { title: t('规则 ID'), dataIndex: 'id', copyable: true },
    { title: t('描述'), dataIndex: 'description' },
    {
      title: t('级别'),
      dataIndex: 'level',
      render: (_, r) => <Tag color={LEVEL_COLOR[r.level]}>{r.level}</Tag>,
    },
    { title: t('冷却（分钟）'), dataIndex: 'cooldown_minutes' },
    {
      title: t('启用'),
      dataIndex: 'enabled',
      render: (_, r) => <Switch checked={r.enabled} onChange={(v) => toggleRule(r.id, v)} />,
    },
  ];

  const activeColumns: ProColumns<ActiveAlert>[] = [
    { title: t('规则'), dataIndex: 'rule_id' },
    {
      title: t('级别'),
      dataIndex: 'level',
      render: (_, r) => <Tag color={LEVEL_COLOR[r.level]}>{r.level}</Tag>,
    },
    { title: t('详情'), dataIndex: 'detail', ellipsis: true },
    { title: t('触发时间'), dataIndex: 'fired_at' },
    { title: t('最近通知'), dataIndex: 'last_notified_at' },
  ];

  const historyColumns: ProColumns<HistoryAlert>[] = [
    { title: t('时间'), dataIndex: 'event_time', valueType: 'dateTime', hideInSearch: true },
    { title: t('规则'), dataIndex: 'rule_id', hideInSearch: true },
    {
      title: t('级别'),
      dataIndex: 'level',
      render: (_, r) => <Tag color={LEVEL_COLOR[r.level]}>{r.level}</Tag>,
    },
    {
      title: t('事件'),
      dataIndex: 'event',
      render: (_, r) => (
        <Tag color={r.event === 'resolved' ? 'green' : r.event === 'muted' ? 'default' : 'red'}>
          {EVENT_TEXT[r.event] ?? r.event}
        </Tag>
      ),
    },
    { title: t('详情'), dataIndex: 'detail', ellipsis: true, hideInSearch: true },
    { title: t('通知渠道'), dataIndex: 'notified_channels', hideInSearch: true },
  ];

  return (
    <PageContainer title={t('告警中心')} subTitle={t('规则目录 / 活动告警 / 历史与维护模式（30s 自动刷新）')}>
      {maintUntil && (
        <div style={{ marginBottom: 16 }}>
          <Tag color="purple">维护模式至 {maintUntil}</Tag>
          <Popconfirm title={t('取消维护模式？')} onConfirm={cancelMaintenance}>
            <Button size="small">{t('取消')}</Button>
          </Popconfirm>
        </div>
      )}
      <div style={{ marginBottom: 8, display: 'flex', gap: 8 }}>
        <Button onClick={() => setMaintenance(2)}>{t('维护模式 2h')}</Button>
        <Button onClick={() => setMaintenance(8)}>8h</Button>
      </div>

      <ProTable<AlertRule>
        headerTitle="规则目录"
        rowKey="id"
        columns={ruleColumns}
        dataSource={rules}
        search={false}
        cardBordered
        pagination={false}
        polling={30000}
        request={async () => {
          const d = await http.get<never, AlertRule[]>('/alerts/rules');
          return { data: d, success: true };
        }}
      />

      <ProTable<ActiveAlert>
        headerTitle={<Space>{t('活动告警')}<Badge count={active.length} /></Space>}
        rowKey="dedup_key"
        columns={activeColumns}
        dataSource={active}
        search={false}
        cardBordered
        style={{ marginTop: 16 }}
        pagination={false}
        locale={{ emptyText: t('当前无活动告警') }}
      />

      <ProTable<HistoryAlert>
        headerTitle="告警历史（本月）"
        rowKey="event_time"
        columns={historyColumns}
        search={false}
        cardBordered
        style={{ marginTop: 16 }}
        request={async (params) => {
          const d = await http.get<never, { list: HistoryAlert[]; total: number }>(
            '/alerts/history',
            { params: { page: params.current ?? 1, pageSize: params.pageSize ?? 20 } },
          );
          return { data: d.list, total: d.total, success: true };
        }}
      />
    </PageContainer>
  );
}
