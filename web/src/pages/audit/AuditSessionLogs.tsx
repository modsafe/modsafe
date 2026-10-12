import { PageContainer } from '@ant-design/pro-components';
import { t } from '../../i18n';
import { ProTable, type ProColumns } from '@ant-design/pro-components';
import http, { type PageData } from '../../api/client';
import { Button } from 'antd';
import { exportCsv } from '../../api/exportCsv';
import { formatBytes } from '../../utils/format';

interface SessionLog {
  connected_at: string;
  username: string;
  virtual_ip: string;
  trusted_ip: string;
  bytes_in: number;
  bytes_out: number;
  last_seen: string;
  state: string;
  node: string;
}

const columns: ProColumns<SessionLog>[] = [
  { title: t('连接时间'), dataIndex: 'connected_at', valueType: 'dateTime', width: 160 },
  { title: t('用户'), dataIndex: 'username' },
  { title: t('虚拟 IP'), dataIndex: 'virtual_ip', copyable: true },
  { title: t('来源 IP'), dataIndex: 'trusted_ip' },
  { title: t('上传'), dataIndex: 'bytes_in', hideInSearch: true, render: (_, r) => formatBytes(r.bytes_in) },
  { title: t('下载'), dataIndex: 'bytes_out', hideInSearch: true, render: (_, r) => formatBytes(r.bytes_out) },
  { title: t('最近活动'), dataIndex: 'last_seen', valueType: 'dateTime' },
  {
    title: t('状态'),
    dataIndex: 'state',
    valueEnum: { 在线: { text: t('在线'), status: 'Success' }, 已结束: { text: t('已结束') } },
  },
  { title: t('节点'), dataIndex: 'node' },
];

export default function AuditSessionLogs() {
  return (
    <PageContainer title={t('会话日志')} subTitle={t('全部连接/断开结算记录 · 留存 ≥6 个月')}>
      <ProTable<SessionLog>
        rowKey={(r) => r.connected_at + r.virtual_ip + r.trusted_ip}
        columns={columns}
        cardBordered
        search={{ labelWidth: 'auto' }}
        request={async (params) => {
          const data = await http.get<never, PageData<SessionLog>>('/audit/session-logs', {
            params: {
              page: params.current,
              pageSize: params.pageSize,
              username: params.username,
            },
          });
          return { data: data.list, total: data.total, success: true };
        }}
        toolBarRender={() => [
          <Button key="csv" onClick={() => exportCsv('/audit/session-logs/export', 'session-logs.csv')}>
            {t('导出 CSV')}
          </Button>,
        ]}
        pagination={{ defaultPageSize: 20 }}
      />
    </PageContainer>
  );
}
