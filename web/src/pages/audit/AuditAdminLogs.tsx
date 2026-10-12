import { PageContainer } from '@ant-design/pro-components';
import { t } from '../../i18n';
import { ProTable, type ProColumns } from '@ant-design/pro-components';
import { Tag } from 'antd';
import http, { type PageData } from '../../api/client';
import { Button } from 'antd';
import { exportCsv } from '../../api/exportCsv';

interface AdminLog {
  event_time: string;
  admin: string;
  method: string;
  path: string;
  client_ip: string;
}

const METHOD_COLOR: Record<string, string> = {
  POST: 'processing',
  PUT: 'warning',
  DELETE: 'error',
  PATCH: 'warning',
};

const columns: ProColumns<AdminLog>[] = [
  { title: t('时间'), dataIndex: 'event_time', valueType: 'dateTime', width: 160 },
  { title: t('管理员'), dataIndex: 'admin' },
  {
    title: t('方法'),
    dataIndex: 'method',
    render: (_, record) => <Tag color={METHOD_COLOR[record.method] ?? 'default'}>{record.method}</Tag>,
  },
  { title: t('操作路径'), dataIndex: 'path', copyable: true },
  { title: t('来源 IP'), dataIndex: 'client_ip' },
];

export default function AuditAdminLogs() {
  return (
    <PageContainer
      title={t('管理操作日志')}
      subTitle={t('管理员全部写操作（仅审计员可见 · 三权分立 §12.3）')}
    >
      <ProTable<AdminLog>
        rowKey={(r) => r.event_time + r.path + r.admin}
        columns={columns}
        cardBordered
        search={false}
        request={async (params) => {
          const data = await http.get<never, PageData<AdminLog>>('/audit/admin-logs', {
            params: { page: params.current, pageSize: params.pageSize },
          });
          return { data: data.list, total: data.total, success: true };
        }}
        toolBarRender={() => [
          <Button key="csv" onClick={() => exportCsv('/audit/admin-logs/export', 'admin-logs.csv')}>
            {t('导出 CSV')}
          </Button>,
        ]}
        pagination={{ defaultPageSize: 20 }}
      />
    </PageContainer>
  );
}
