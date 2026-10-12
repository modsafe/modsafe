import { PageContainer } from '@ant-design/pro-components';
import { t } from '../../i18n';
import { ProTable, type ProColumns } from '@ant-design/pro-components';
import { Button } from 'antd';
import http, { type PageData } from '../../api/client';
import { exportCsv } from '../../api/exportCsv';

interface AuthLog {
  event_time: string;
  username: string;
  idp_source: string;
  result: string;
  reason: string;
  trusted_ip: string;
}

const columns: ProColumns<AuthLog>[] = [
  { title: t('时间'), dataIndex: 'event_time', valueType: 'dateTime', width: 160 },
  { title: t('用户名'), dataIndex: 'username' },
  {
    title: t('来源'),
    dataIndex: 'idp_source',
    valueEnum: {
      dingtalk: { text: t('钉钉') },
      wecom: { text: t('企业微信') },
      feishu: { text: t('飞书') },
      'ldap-ad': { text: 'AD' },
      openldap: { text: 'OpenLDAP' },
      local: { text: t('本地') },
    },
  },
  {
    title: t('结果'),
    dataIndex: 'result',
    valueEnum: {
      success: { text: t('成功'), status: 'Success' },
      fail: { text: t('失败'), status: 'Error' },
      deny: { text: t('拒绝'), status: 'Error' },
    },
  },
  { title: t('原因'), dataIndex: 'reason', ellipsis: true },
  { title: t('来源 IP'), dataIndex: 'trusted_ip' },
];

export default function AuditAuthLogs() {
  return (
    <PageContainer title={t('认证日志')} subTitle={t('全部认证事件（含 IM 扫码、本地账号、自动建档、禁用拒绝）· 留存 ≥6 个月')}>
      <ProTable<AuthLog>
        rowKey={(r) => r.event_time + r.username + r.trusted_ip}
        columns={columns}
        cardBordered
        search={{ labelWidth: 'auto' }}
        request={async (params) => {
          const data = await http.get<never, PageData<AuthLog>>('/audit/auth-logs', {
            params: {
              page: params.current,
              pageSize: params.pageSize,
              username: params.username,
              source: params.idp_source,
              result: params.result,
            },
          });
          return { data: data.list, total: data.total, success: true };
        }}
        toolBarRender={() => [
          <Button key="csv" onClick={() => exportCsv('/audit/auth-logs/export', 'auth-logs.csv')}>
            {t('导出 CSV')}
          </Button>,
        ]}
        pagination={{ defaultPageSize: 20 }}
      />
    </PageContainer>
  );
}
