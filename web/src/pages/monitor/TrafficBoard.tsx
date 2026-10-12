import { PageContainer } from '@ant-design/pro-components';
import { t } from '../../i18n';
import { Card, Col, Row, Segmented, Statistic, Table } from 'antd';
import { ArrowDownOutlined, ArrowUpOutlined, LinkOutlined } from '@ant-design/icons';
import { useEffect, useState } from 'react';
import ReactECharts from 'echarts-for-react';
import http from '../../api/client';
import { formatBytes } from '../../utils/format';

interface TrafficPoint {
  time: string;
  rx_mb: number;
  tx_mb: number;
}
interface OnlinePoint {
  time: string;
  online: number;
}
interface TopUser {
  username: string;
  bytes_in: number;
  bytes_out: number;
  sessions: number;
}
interface TrafficResp {
  range: string;
  total_in: number;
  total_out: number;
  sessions: number;
  top_users: TopUser[];
  traffic_series: TrafficPoint[];
  online_series: OnlinePoint[];
}

type RangeKey = 'today' | '7d' | '30d';
const RANGE_LABEL: Record<RangeKey, string> = { today: t('今日'), '7d': t('近 7 天'), '30d': t('近 30 天') };

export default function TrafficBoard() {
  const [range, setRange] = useState<RangeKey>('today');
  const [data, setData] = useState<TrafficResp | null>(null);

  useEffect(() => {
    http
      .get<never, TrafficResp>('/monitor/traffic', { params: { range } })
      .then(setData)
      .catch(() => {});
  }, [range]);

  const trafficOption = {
    tooltip: { trigger: 'axis' },
    legend: { data: [t('上行 (入站)'), t('下行 (出站)')] },
    grid: { left: 48, right: 24, top: 40, bottom: 28 },
    xAxis: { type: 'category', data: (data?.traffic_series ?? []).map((p) => p.time) },
    yAxis: { type: 'value', name: 'MB' },
    series: [
      {
        name: t('上行 (入站)'),
        type: 'line',
        smooth: true,
        showSymbol: false,
        areaStyle: { opacity: 0.12 },
        data: (data?.traffic_series ?? []).map((p) => p.rx_mb),
      },
      {
        name: t('下行 (出站)'),
        type: 'line',
        smooth: true,
        showSymbol: false,
        areaStyle: { opacity: 0.12 },
        data: (data?.traffic_series ?? []).map((p) => p.tx_mb),
      },
    ],
  };

  const onlineOption = {
    tooltip: { trigger: 'axis' },
    grid: { left: 48, right: 24, top: 24, bottom: 28 },
    xAxis: { type: 'category', data: (data?.online_series ?? []).map((p) => p.time) },
    yAxis: { type: 'value', minInterval: 1 },
    series: [
      {
        name: t('在线用户峰值'),
        type: 'line',
        smooth: true,
        showSymbol: false,
        areaStyle: { opacity: 0.12 },
        data: (data?.online_series ?? []).map((p) => p.online),
      },
    ],
  };

  const top = data?.top_users ?? [];
  const maxTotal = top.reduce((m, u) => Math.max(m, u.bytes_in + u.bytes_out), 0);

  return (
    <PageContainer
      title={t('流量看板')}
      subTitle={t('集群流量趋势与用户排行；曲线口径 = 双节点活跃会话 24h 差分（30 分钟桶）')}
      extra={[
        <Segmented
          key="range"
          value={range}
          onChange={(v) => setRange(v as RangeKey)}
          options={(Object.keys(RANGE_LABEL) as RangeKey[]).map((k) => ({ label: RANGE_LABEL[k], value: k }))}
        />,
      ]}
    >
      <Row gutter={16}>
        <Col xs={24} sm={8}>
          <Card>
            <Statistic
              title={t('{v0}上行总量（用户上传）', { v0: RANGE_LABEL[range] })}
              value={data ? formatBytes(data.total_in) : '-'}
              prefix={<ArrowUpOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={8}>
          <Card>
            <Statistic
              title={t('{v0}下行总量（用户下载）', { v0: RANGE_LABEL[range] })}
              value={data ? formatBytes(data.total_out) : '-'}
              prefix={<ArrowDownOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={8}>
          <Card>
            <Statistic title={t('{v0}会话次数', { v0: RANGE_LABEL[range] })} value={data?.sessions ?? '-'} prefix={<LinkOutlined />} />
          </Card>
        </Col>
      </Row>
      <Card title={t('24 小时流量趋势')} style={{ marginTop: 16 }}>
        <ReactECharts option={trafficOption} style={{ height: 300 }} />
      </Card>
      <Row gutter={16} style={{ marginTop: 16 }}>
        <Col xs={24} lg={14}>
          <Card title={t('用户流量排行 Top 20（{v0}）', { v0: RANGE_LABEL[range] })}>
            <Table<TopUser>
              rowKey="username"
              size="small"
              pagination={false}
              dataSource={top}
              locale={{ emptyText: t('暂无数据（等待用户连接产生流量）') }}
              columns={[
                { title: t('用户'), dataIndex: 'username' },
                { title: t('上行'), dataIndex: 'bytes_in', render: (_, r) => formatBytes(r.bytes_in) },
                { title: t('下行'), dataIndex: 'bytes_out', render: (_, r) => formatBytes(r.bytes_out) },
                { title: t('会话'), dataIndex: 'sessions', width: 72 },
                {
                  title: t('占比'),
                  width: 160,
                  render: (_, r) => {
                    const pct = maxTotal > 0 ? Math.round(((r.bytes_in + r.bytes_out) / maxTotal) * 100) : 0;
                    return <div style={{ background: '#f0f0f0', borderRadius: 4 }}><div style={{ width: `${pct}%`, minWidth: 2, height: 8, background: '#1677ff', borderRadius: 4 }} /></div>;
                  },
                },
              ]}
            />
          </Card>
        </Col>
        <Col xs={24} lg={10}>
          <Card title={t('24 小时在线峰值')}>
            <ReactECharts option={onlineOption} style={{ height: 300 }} />
          </Card>
        </Col>
      </Row>
    </PageContainer>
  );
}
