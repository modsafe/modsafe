import { PageContainer } from '@ant-design/pro-components';
import { t } from '../../i18n';
import { ProTable, type ProColumns, type ActionType } from '@ant-design/pro-components';
import { Card, Tag, App, Statistic, Row, Col, Modal, Descriptions } from 'antd';
import { useRef, useState, useEffect } from 'react';
import http, { type PageData } from '../../api/client';

interface CertInfo {
  subca_cn: string;
  subca_not_after: string;
  subca_days_left: number;
  root_offline: boolean;
}

interface DeviceRow {
  id: number;
  user_id: number;
  cert_cn: string;
  platform: string;
  device_name: string;
  status: string;
  created_at: string;
  fingerprint?: string;
}

interface DeviceDetail extends DeviceRow {
  cert_pem: string;
  last_used_at: string | null;
}

export default function Certificates() {
  const actionRef = useRef<ActionType>(null);
  const { message, modal } = App.useApp();
  const [info, setInfo] = useState<CertInfo | null>(null);
  const [detail, setDetail] = useState<DeviceDetail | null>(null);

  useEffect(() => {
    http.get<never, CertInfo>('/certs/info').then(setInfo).catch(() => {});
  }, []);

  const showDetail = async (id: number) => {
    const d = await http.get<never, DeviceDetail>(`/devices/${id}`);
    setDetail(d);
  };

  const revoke = (row: DeviceRow) => {
    modal.confirm({
      title: t('吊销设备「{v0}」的证书？', { v0: row.device_name || row.cert_cn }),
      content: t('将标记吊销、全节点踢线，且不可再用于生成新配置。（TLS 层 CRL 校验为后续项）'),
      okButtonProps: { danger: true },
      onOk: async () => {
        const res = await http.post<never, { notice: string }>(`/devices/${row.id}/revoke`, {});
        message.success(res.notice || t('已吊销'));
        actionRef.current?.reload();
      },
    });
  };

  const columns: ProColumns<DeviceRow>[] = [
    { title: 'ID', dataIndex: 'id', width: 60 },
    { title: t('证书 CN（用户）'), dataIndex: 'cert_cn', copyable: true },
    { title: t('设备名'), dataIndex: 'device_name' },
    { title: t('平台'), dataIndex: 'platform' },
    {
      title: t('状态'),
      dataIndex: 'status',
      valueEnum: {
        active: { text: t('有效'), status: 'Success' },
        revoked: { text: t('已吊销'), status: 'Error' },
      },
    },
    { title: t('签发时间'), dataIndex: 'created_at', valueType: 'dateTime' },
    {
      title: t('操作'),
      valueType: 'option',
      render: (_, record) => (
        <>
          <a onClick={() => showDetail(record.id)}>{t('证书详情')}</a>
          {record.status === 'active' && (
            <>
              <a> </a>
              <a onClick={() => revoke(record)}>{t('吊销')}</a>
            </>
          )}
        </>
      ),
    },
  ];

  return (
    <PageContainer
      title={t('证书管理')}
      subTitle={t('客户端证书设备台账（§15 在线签发：root 离线 + 在线子 CA 两级体系）')}
    >
      <Card style={{ marginBottom: 16 }}>
        <Row gutter={16}>
          <Col span={6}>
            <Statistic title={t('签发 CA')} value={info?.subca_cn ?? '—'} />
          </Col>
          <Col span={6}>
            <Statistic
              title={t('子 CA 到期')}
              value={info ? t('{v0} 天', { v0: info.subca_days_left }) : '—'}
              suffix={info ? `(${info.subca_not_after})` : ''}
            />
          </Col>
          <Col span={6}>
            <Statistic title="Root CA" value="离线保管" />
          </Col>
          <Col span={6}>
            <Statistic title={t('信任链')} value="Root + SubCA（双级）" />
          </Col>
        </Row>
      </Card>

      <ProTable<DeviceRow>
        rowKey="id"
        actionRef={actionRef}
        columns={columns}
        search={false}
        cardBordered
        request={async (params) => {
          // 复用会话台账聚合接口字段不足以展示 devices 全量，直接用 cert 列表语义：
          // /devices 返回聚合视图；证书页需要 devices 表 → 用 /devices + 展开补充
          const data = await http.get<never, PageData<DeviceRow>>('/certs/devices', {
            params: { page: params.current, pageSize: params.pageSize },
          });
          return { data: data.list, total: data.total, success: true };
        }}
        pagination={{ defaultPageSize: 20 }}
      />

      <Modal
        title={t('证书详情 — {v0}', { v0: detail?.cert_cn ?? '' })}
        open={!!detail}
        onCancel={() => setDetail(null)}
        footer={null}
        width={640}
      >
        {detail && (
          <>
            <Descriptions column={2} size="small" bordered style={{ marginBottom: 12 }}>
              <Descriptions.Item label={t('设备名')}>{detail.device_name}</Descriptions.Item>
              <Descriptions.Item label={t('平台')}>{detail.platform || '—'}</Descriptions.Item>
              <Descriptions.Item label={t('状态')}>
                <Tag color={detail.status === 'active' ? 'green' : 'red'}>
                  {detail.status === 'active' ? t('有效') : t('已吊销')}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label={t('签发时间')}>{detail.created_at}</Descriptions.Item>
            </Descriptions>
            <pre
              style={{
                background: '#0b1021', color: '#7fdbca', padding: 12,
                borderRadius: 6, fontSize: 11, maxHeight: 300, overflow: 'auto',
              }}
            >
              {detail.cert_pem || t('（无）')}
            </pre>
          </>
        )}
      </Modal>
    </PageContainer>
  );
}
