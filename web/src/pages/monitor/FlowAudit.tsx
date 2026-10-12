import { PageContainer } from '@ant-design/pro-components';
import { t } from '../../i18n';
import { Button, Card, Col, Row, Segmented, Statistic, Table, Input, Tag } from 'antd';
import { useEffect, useState } from 'react';
import http from '../../api/client';
import { exportCsv } from '../../api/exportCsv';
import { formatBytes } from '../../utils/format';

interface LiveFlow {
  node: string;
  src: string;
  dst: string;
  proto: string;
  port: number;
  bytes: number;
  username: string;
  domain?: string;
  first_seen?: string;
  last_seen?: string;
  trusted_ip?: string;
}

interface DnsRow {
  ts: string;
  src: string;
  domain: string;
  qtype: string;
  username: string;
}

interface HistRow {
  username: string;
  dst: string;
  port: number;
  proto: string;
  bytes: number;
  conns: number;
  domain?: string;
  last_seen?: string;
}

interface TopUser {
  username: string;
  bytes: number;
}

// 常见端口→服务名（后端同款映射）
const SVC: Record<number, string> = {
  22: 'SSH', 53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
  1433: 'MSSQL', 3389: 'RDP', 5228: 'Google Push', 5432: 'PostgreSQL',
  6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB',
};
const svc = (p: number) => SVC[p] || `${p}`;

export default function FlowAudit() {
  const [live, setLive] = useState<LiveFlow[]>([]);
  const [polledAt, setPolledAt] = useState('');
  const [range, setRange] = useState<'today' | '7d'>('today');
  const [user, setUser] = useState('');
  const [hist, setHist] = useState<HistRow[]>([]);
  const [top, setTop] = useState<TopUser[]>([]);
  const [dns, setDns] = useState<DnsRow[]>([]);

  // DNS 查询记录：默认加载最近 60 条（#78 修复：此前必须输入过滤才加载，卡片恒空），
  // 输入用户名后转为服务端过滤
  useEffect(() => {
    const q = new URLSearchParams({ limit: '60' });
    if (user) q.set('username', user);
    http.get<never, { list: DnsRow[] }>(`/monitor/audit/dns?${q}`)
      .then((d) => setDns(d.list || [])).catch(() => {});
  }, [user]);

  useEffect(() => {
    const load = () => http.get<never, { list: LiveFlow[]; polled_at: string }>('/monitor/audit/flows')
      .then((d) => { setLive(d.list || []); setPolledAt(d.polled_at || ''); }).catch(() => {});
    load();
    const t = window.setInterval(load, 30000);
    return () => window.clearInterval(t);
  }, []);

  useEffect(() => {
    const q = new URLSearchParams({ range, limit: '80' });
    if (user) q.set('username', user);
    http.get<never, { list: HistRow[]; top_users?: TopUser[] }>(`/monitor/audit/history?${q}`)
      .then((d) => { setHist(d.list || []); setTop(d.top_users || []); }).catch(() => {});
  }, [range, user]);

  const liveCols = [
    { title: t('用户'), dataIndex: 'username', copyable: true },
    { title: t('接入 IP'), dataIndex: 'trusted_ip', copyable: true, render: (v: string) => v || '-' },
    { title: t('目的地址'), dataIndex: 'dst', copyable: true },
    { title: t('域名'), dataIndex: 'domain', render: (v: string) => v ? <Tag color="purple">{v}</Tag> : '-' },
    { title: t('服务'), render: (_: unknown, r: LiveFlow) => <Tag color="blue">{svc(r.port)}</Tag> },
    { title: t('协议'), dataIndex: 'proto', width: 90 },
    { title: t('首次出现'), dataIndex: 'first_seen', width: 160, render: (v: string) => v || '-' },
    { title: t('最近活动'), dataIndex: 'last_seen', width: 160, render: (v: string) => v || '-' },
    { title: t('流量'), dataIndex: 'bytes', render: (v: number) => formatBytes(v), sorter: (a: LiveFlow, b: LiveFlow) => a.bytes - b.bytes, defaultSortOrder: 'descend' as const },
    { title: t('节点'), dataIndex: 'node', width: 100 },
  ];

  const histCols = [
    { title: t('用户'), dataIndex: 'username', copyable: true },
    { title: t('目的地址'), dataIndex: 'dst', copyable: true },
    { title: t('域名'), dataIndex: 'domain', render: (v: string) => v ? <Tag color="purple">{v}</Tag> : '-' },
    { title: t('服务'), render: (_: unknown, r: HistRow) => <Tag color="blue">{svc(r.port)}</Tag> },
    { title: t('协议'), dataIndex: 'proto', width: 90 },
    { title: t('最近活动'), dataIndex: 'last_seen', width: 160, render: (v: string) => v || '-' },
    { title: t('流量'), dataIndex: 'bytes', render: (v: number) => formatBytes(v), sorter: (a: HistRow, b: HistRow) => a.bytes - b.bytes, defaultSortOrder: 'descend' as const },
    { title: t('连接数'), dataIndex: 'conns', width: 100 },
  ];

  return (
    <PageContainer title={t('流量审计')} subTitle={t('用户访问了哪些目标（连接级，conntrack 30s 采样聚合）')}>
      <Row gutter={16} style={{ marginBottom: 16 }}>
        <Col span={8}>
          <Card><Statistic title={t('实时连接流')} value={live.length} suffix={polledAt ? `@ ${polledAt}` : ''} /></Card>
        </Col>
        <Col span={16}>
          <Card>
            <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
              <Segmented options={[{ label: t('今日'), value: 'today' }, { label: t('近 7 天'), value: '7d' }]} value={range} onChange={(v) => setRange(v as 'today' | '7d')} />
              <Input.Search
                allowClear
                placeholder={t('按用户名过滤')}
                style={{ width: 240 }}
                onSearch={(v) => setUser(v.trim())}
              />
            </div>
          </Card>
        </Col>
      </Row>

      <Card title={t('按用户/目的聚合')} style={{ marginBottom: 16 }}>
        {top.length > 0 && (
          <div style={{ marginBottom: 12 }}>
            {top.map((u) => (
              <Tag key={u.username} color="geekblue">{u.username} · {formatBytes(u.bytes)}</Tag>
            ))}
          </div>
        )}
        <Table<HistRow>
          rowKey={(r) => r.username + r.dst + r.port + r.proto}
          columns={histCols}
          dataSource={hist}
          pagination={{ pageSize: 10, showSizeChanger: false }}
          size="small"
        />
      </Card>

      <Card title={t('实时连接（最近一轮采样）')} style={{ marginBottom: 16 }}>
        <Table<LiveFlow>
          rowKey={(r) => r.src + r.dst + r.port + r.proto}
          columns={liveCols}
          dataSource={live}
          pagination={{ pageSize: 10, showSizeChanger: false }}
          size="small"
        />
      </Card>

      <Card
        title={t('DNS 查询记录（最近 60 条）')}
        extra={
          <Button size="small" onClick={() => exportCsv('/monitor/audit/dns/export', 'dns-queries.csv')}>
            {t('导出 CSV')}
          </Button>
        }
      >
        <Table<DnsRow>
          rowKey={(r) => r.ts + r.src + r.domain + r.qtype}
          columns={[
            { title: t('时间'), dataIndex: 'ts', width: 170 },
            { title: t('用户'), dataIndex: 'username', render: (v: string) => v || '-' },
            { title: t('来源'), dataIndex: 'src', width: 130 },
            { title: t('域名'), dataIndex: 'domain', render: (v: string) => <Tag>{v}</Tag> },
            { title: t('类型'), dataIndex: 'qtype', width: 80 },
          ]}
          dataSource={dns}
          pagination={{ pageSize: 8, hideOnSinglePage: true }}
          size="small"
        />
      </Card>
    </PageContainer>
  );
}
