import { PageContainer } from '@ant-design/pro-components';
import { t } from '../../i18n';
import { ProTable, type ProColumns } from '@ant-design/pro-components';
import { Button, message } from 'antd';
import http, { type PageData } from '../../api/client';
import type { SessionItem } from '../../api/types';
import { formatBytes } from '../../utils/format';

const columns: ProColumns<SessionItem>[] = [
  { title: t('用户'), dataIndex: 'username', copyable: true },
  { title: t('虚拟 IP'), dataIndex: 'virtual_ip', copyable: true },
  { title: t('来源 IP'), dataIndex: 'trusted_ip', hideInSearch: true },
  { title: t('连接时间'), dataIndex: 'connected_at', hideInSearch: true, valueType: 'dateTime' },
  { title: t('上传'), dataIndex: 'bytes_in', hideInSearch: true, render: (_, r) => formatBytes(r.bytes_in) },
  { title: t('下载'), dataIndex: 'bytes_out', hideInSearch: true, render: (_, r) => formatBytes(r.bytes_out) },
  { title: t('节点'), dataIndex: 'node', hideInSearch: true },
  {
    title: t('操作'),
    valueType: 'option',
    render: (_, record) => (
      <a
        onClick={async () => {
          await http.post('/monitor/sessions/kick', {
            username: record.username,
            node: record.node,
          });
          message.success(t('已下线 {v0}（{v1} @ {v2}）', { v0: record.username, v1: record.virtual_ip, v2: record.node }));
        }}
      >
        强制下线
      </a>
    ),
  },
];

export default function Sessions() {
  return (
    <PageContainer
      title={t('在线用户')}
      subTitle={t('实时连接列表（15s 自动刷新）；接口 GET /monitor/sessions')}
    >
      <ProTable<SessionItem>
        rowKey="virtual_ip"
        columns={columns}
        search={false}
        cardBordered
        polling={15000}
        request={async (params) => {
          const data = await http.get<never, PageData<SessionItem>>('/monitor/sessions', {
            params: { page: params.current, pageSize: params.pageSize },
          });
          return { data: data.list, total: data.total, success: true };
        }}
        toolBarRender={() => [
          <Button key="kick-hint" onClick={() => message.info(t('选中行可强制下线（management client-kill）'))}>
            操作说明
          </Button>,
        ]}
      />
    </PageContainer>
  );
}
