import { PageContainer } from '@ant-design/pro-components';
import { t } from '../../i18n';
import { ProTable, type ProColumns } from '@ant-design/pro-components';
import { Tag, App } from 'antd';
import { useRef } from 'react';
import type { ActionType } from '@ant-design/pro-components';
import http, { type PageData } from '../../api/client';
import { formatBytes } from '../../utils/format';

interface DeviceRow {
  username: string;
  trusted_ip: string;
  last_virtual_ip: string;
  node: string;
  first_seen: string;
  last_seen: string;
  online: boolean;
  total_bytes_in: number;
  total_bytes_out: number;
  session_count: number;
}

export default function Devices() {
  const actionRef = useRef<ActionType>(null);
  const { message, modal } = App.useApp();

  const columns: ProColumns<DeviceRow>[] = [
    { title: t('用户'), dataIndex: 'username', copyable: true },
    { title: t('来源 IP'), dataIndex: 'trusted_ip', copyable: true },
    { title: t('最近虚拟 IP'), dataIndex: 'last_virtual_ip' },
    {
      title: t('状态'),
      dataIndex: 'online',
      hideInSearch: true,
      valueEnum: { true: { text: t('在线'), status: 'Success' }, false: { text: t('离线'), status: 'Default' } },
      render: (_, r) => <Tag color={r.online ? 'green' : 'default'}>{r.online ? t('在线') : t('离线')}</Tag>,
    },
    { title: t('累计上传'), dataIndex: 'total_bytes_in', hideInSearch: true, render: (_, r) => formatBytes(r.total_bytes_in) },
    { title: t('累计下载'), dataIndex: 'total_bytes_out', hideInSearch: true, render: (_, r) => formatBytes(r.total_bytes_out) },
    { title: t('会话次数'), dataIndex: 'session_count', hideInSearch: true },
    { title: t('节点'), dataIndex: 'node', hideInSearch: true },
    { title: t('最近活动'), dataIndex: 'last_seen', hideInSearch: true, valueType: 'dateTime' },
    {
      title: t('操作'),
      valueType: 'option',
      render: (_, record) =>
        record.online ? (
          <a
            onClick={async () => {
              modal.confirm({
                title: t('强制下线 {v0}（{v1}）？', { v0: record.username, v1: record.trusted_ip }),
                onOk: async () => {
                  await http.post('/monitor/sessions/kick', {
                    username: record.username,
                    node: record.node,
                  });
                  message.success(t('已下线'));
                  actionRef.current?.reload();
                },
              });
            }}
          >
            强制下线
          </a>
        ) : null,
    },
  ];

  return (
    <PageContainer
      title={t('设备管理')}
      subTitle={t('按「用户 + 来源 IP」聚合的接入来源台账（来自会话追踪；证书级设备管理随客户端签发功能上线）')}
    >
      <ProTable<DeviceRow>
        rowKey={(r) => r.username + r.trusted_ip}
        actionRef={actionRef}
        columns={columns}
        search={false}
        cardBordered
        request={async (params) => {
          const data = await http.get<never, PageData<DeviceRow>>('/devices', {
            params: { page: params.current, pageSize: params.pageSize },
          });
          return { data: data.list, total: data.total, success: true };
        }}
        pagination={{ defaultPageSize: 20 }}
      />
    </PageContainer>
  );
}
