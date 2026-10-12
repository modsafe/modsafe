import { PageContainer } from '@ant-design/pro-components';
import { t } from '../../i18n';
import { Alert, Badge, Card, Col, List, Row, Statistic, Table, Tag } from 'antd';
import { useEffect, useState } from 'react';
import http from '../../api/client';
import { formatBytes } from '../../utils/format';

interface NodeState {
  name: string;
  host: string;
  active: boolean;
  online: number;
  live_online: number;
  bytes_rx: number;
  bytes_tx: number;
  data_age_seconds: number;
}
interface CertItem {
  file: string;
  days_left: number;
  status: string;
}
interface AlertItem {
  ts: number;
  level: string;
  message: string;
}
interface NodesResp {
  collector_alive: boolean;
  nodes: NodeState[];
  certs: CertItem[];
  alerts: AlertItem[];
  vip: { address: string; held_by_local: boolean; interface: string; keepalived_active: boolean };
}

function fmtTime(ts: number): string {
  return new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false });
}

const levelColor: Record<string, string> = { critical: 'red', warn: 'orange', info: 'blue' };

export default function NodeStatus() {
  const [data, setData] = useState<NodesResp | null>(null);

  useEffect(() => {
    const load = () => http.get<never, NodesResp>('/monitor/nodes').then(setData).catch(() => {});
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, []);

  const vip = data?.vip;

  return (
    <PageContainer title={t('节点状态')} subTitle={t('双节点集群与 director 健康快照（15s 自动刷新）')}>
      {!data?.collector_alive && (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 16 }}
          message={t('监控采集器（modsec-monitor :7505）不可达')}
          description={t('节点卡片显示实时会话数（不依赖采集器），但历史指标与告警不可用。请在 180 上检查 systemctl status modsec-monitor。')}
        />
      )}
      <Row gutter={16}>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title={t('虚拟服务（VIP）')}
              value={vip?.address ?? '-'}
              prefix={<Badge status={vip?.keepalived_active ? 'success' : 'error'} />}
              valueStyle={{ fontSize: 20 }}
            />
            <div style={{ marginTop: 8, color: '#888', fontSize: 12 }}>
              keepalived {vip?.keepalived_active ? t('运行中') : t('异常')}；本机{vip?.held_by_local ? `持有 VIP（${vip.interface}）= MASTER` : t('未持有（DR 模式下 lo 的 .140/32 为 RS 常驻配置，非真持有）')}
            </div>
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic title={t('集群在线会话（实时）')} value={data?.nodes.reduce((s, n) => s + n.live_online, 0) ?? '-'} />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title={t('健康节点')}
              value={data ? `${data.nodes.filter((n) => n.active).length}/${data.nodes.length}` : '-'}
              valueStyle={{ color: data && data.nodes.every((n) => n.active) ? '#52c41a' : '#cf1322' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title={t('最近告警')}
              value={data?.alerts.length ?? '-'}
              valueStyle={{ color: (data?.alerts.length ?? 0) > 0 ? '#cf1322' : '#52c41a' }}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={16} style={{ marginTop: 16 }}>
        {(data?.nodes ?? []).map((n) => (
          <Col xs={24} md={12} key={n.name}>
            <Card
              title={
                <span>
                  <Badge status={n.active ? 'success' : 'error'} style={{ marginRight: 8 }} />
                  {n.name}
                  {n.host && <span style={{ color: '#888', fontSize: 12, marginLeft: 8 }}>@{n.host}</span>}
                </span>
              }
            >
              <Row gutter={12}>
                <Col span={6}>
                  <Statistic title={t('在线（采集）')} value={n.online} />
                </Col>
                <Col span={6}>
                  <Statistic title={t('在线（实时）')} value={n.live_online} />
                </Col>
                <Col span={6}>
                  <Statistic title={t('当前会话下行')} value={formatBytes(n.bytes_rx)} valueStyle={{ fontSize: 16 }} />
                </Col>
                <Col span={6}>
                  <Statistic title={t('当前会话上行')} value={formatBytes(n.bytes_tx)} valueStyle={{ fontSize: 16 }} />
                </Col>
              </Row>
              <div style={{ marginTop: 8, color: '#888', fontSize: 12 }}>
                采集数据新鲜度 {n.data_age_seconds >= 0 ? `${n.data_age_seconds}s 前` : t('未知')}
                {n.data_age_seconds > 120 && <Tag color="orange" style={{ marginLeft: 8 }}>{t('数据滞后')}</Tag>}
              </div>
            </Card>
          </Col>
        ))}
      </Row>

      <Row gutter={16} style={{ marginTop: 16 }}>
        <Col xs={24} lg={12}>
          <Card title={t('证书到期（采集器巡检）')}>
            <Table<CertItem>
              rowKey="file"
              size="small"
              pagination={false}
              dataSource={data?.certs ?? []}
              columns={[
                { title: t('证书'), dataIndex: 'file' },
                {
                  title: t('剩余天数'),
                  dataIndex: 'days_left',
                  render: (_, r) =>
                    r.days_left < 0 ? <Tag color="red">{t('读取失败')}</Tag> : <Tag color={r.days_left < 30 ? 'orange' : 'green'}>{r.days_left} 天</Tag>,
                },
              ]}
            />
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card title={t('最近告警（20 条）')}>
            <List
              size="small"
              dataSource={data?.alerts ?? []}
              locale={{ emptyText: t('暂无告警') }}
              renderItem={(item) => (
                <List.Item>
                  <Tag color={levelColor[item.level] ?? 'default'}>{item.level}</Tag>
                  <span style={{ flex: 1 }}>{item.message}</span>
                  <span style={{ color: '#888', fontSize: 12 }}>{fmtTime(item.ts)}</span>
                </List.Item>
              )}
            />
          </Card>
        </Col>
      </Row>
    </PageContainer>
  );
}
