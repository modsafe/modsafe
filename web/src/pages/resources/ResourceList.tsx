import { PageContainer } from '@ant-design/pro-components';
import { t } from '../../i18n';
import { ProTable, type ProColumns, type ActionType } from '@ant-design/pro-components';
import { Button, Space, App, Form, Input, Modal } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { useRef, useState } from 'react';
import http, { type PageData } from '../../api/client';
import type { Resource } from '../../api/types';

export default function ResourceList() {
  const actionRef = useRef<ActionType>(null);
  const { message, modal } = App.useApp();
  const [createOpen, setCreateOpen] = useState(false);
  const [form] = Form.useForm();

  const reload = () => actionRef.current?.reload();

  const createResource = async () => {
    const values = await form.validateFields();
    await http.post('/resources', values);
    message.success(t('资源已创建（组绑定后自动随 CCD 下发）'));
    setCreateOpen(false);
    form.resetFields();
    reload();
  };

  const deleteResource = (res: Resource) => {
    modal.confirm({
      title: t('确认删除资源「{v0}」？', { v0: res.name }),
      content: t('仍被组引用时会被拒绝。'),
      okButtonProps: { danger: true },
      onOk: async () => {
        await http.delete(`/resources/${res.id}`);
        message.success(t('已删除'));
        reload();
      },
    });
  };

  const columns: ProColumns<Resource>[] = [
    { title: t('名称'), dataIndex: 'name' },
    { title: 'CIDR', dataIndex: 'cidr', copyable: true },
    { title: t('描述'), dataIndex: 'description', hideInSearch: true },
    { title: t('被引用组数'), dataIndex: 'ref_count', hideInSearch: true },
    {
      title: t('操作'),
      valueType: 'option',
      render: (_, record) => (
        <Space>
          <a onClick={() => deleteResource(record)}>{t('删除')}</a>
        </Space>
      ),
    },
  ];

  return (
    <PageContainer
      title={t('资源管理')}
      subTitle={t('可授权给组的内网网段（CIDR）；组绑定资源后，成员认证时自动随 CCD 下发路由')}
    >
      <ProTable<Resource>
        rowKey="id"
        actionRef={actionRef}
        columns={columns}
        cardBordered
        request={async (params) => {
          const data = await http.get<never, PageData<Resource>>('/resources', {
            params: { page: params.current, pageSize: params.pageSize, keyword: params.name },
          });
          return { data: data.list, total: data.total, success: true };
        }}
        toolBarRender={() => [
          <Button key="create" type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
            新建资源
          </Button>,
        ]}
        pagination={{ defaultPageSize: 20 }}
      />

      <Modal
        title={t('新建资源')}
        open={createOpen}
        onOk={createResource}
        onCancel={() => setCreateOpen(false)}
        okText={t('创建')}
        destroyOnClose
      >
        <Form form={form} layout="vertical">
          <Form.Item name="name" label={t('名称')} rules={[{ required: true, message: '必填' }]}>
            <Input placeholder={t('如：财务系统网段')} />
          </Form.Item>
          <Form.Item
            name="cidr"
            label="CIDR"
            rules={[
              { required: true, message: t('必填') },
              {
                // IPv4 与 IPv6 CIDR 均可（IPv6 支持 2026-10-02）；最终以后端 netip 严格校验为准
                pattern: /^([0-9a-fA-F:]+\/\d{1,3}|(\d{1,3}\.){3}\d{1,3}\/\d{1,2})$/,
                message: t('格式示例：10.0.1.0/24'),
              },
            ]}
          >
            <Input placeholder={t('10.0.1.0/24 或 IPv6 前缀如 fd00:2026:192::/64（服务端仍会严格校验）')} />
          </Form.Item>
          <Form.Item name="description" label={t('描述')}>
            <Input placeholder={t('可空')} />
          </Form.Item>
        </Form>
      </Modal>
    </PageContainer>
  );
}
