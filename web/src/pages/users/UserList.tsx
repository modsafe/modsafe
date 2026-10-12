import { PageContainer } from '@ant-design/pro-components';
import { t } from '../../i18n';
import { ProTable, type ProColumns } from '@ant-design/pro-components';
import { Button, Tag, Space, App, Form, Input, Modal } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import type { ActionType } from '@ant-design/pro-components';
import http, { type PageData } from '../../api/client';
import type { User, IdpSource } from '../../api/types';

const SOURCE_TEXT: Record<IdpSource, { text: string; color: string }> = {
  local: { text: t('本地'), color: 'default' },
  ldap: { text: 'OpenLDAP', color: 'blue' },
  'ldap-ad': { text: 'AD', color: 'geekblue' },
  dingtalk: { text: t('钉钉'), color: 'processing' },
  wecom: { text: t('企业微信'), color: 'success' },
  feishu: { text: t('飞书'), color: 'purple' },
};

export default function UserList() {
  const navigate = useNavigate();
  const actionRef = useRef<ActionType>(null);
  const { message, modal } = App.useApp();
  const [createOpen, setCreateOpen] = useState(false);
  const [form] = Form.useForm();

  const reload = () => actionRef.current?.reload();

  const toggleStatus = (user: User) => {
    const action = user.status === 'active' ? t('禁用') : t('启用');
    modal.confirm({
      title: t('确认{v0}用户「{v1}」？', { v0: action, v1: user.display_name || user.username }),
      content:
        user.status === 'active'
          ? t('禁用会立即断开该用户全部在线会话，且后续认证被拒绝。')
          : undefined,
      onOk: async () => {
        await http.post(`/users/${user.id}/status`, {
          action: user.status === 'active' ? 'disable' : 'enable',
        });
        message.success(t('{v0}成功', { v0: action }));
        reload();
      },
    });
  };

  const deleteUser = (user: User) => {
    modal.confirm({
      title: t('确认删除用户「{v0}」？', { v0: user.display_name || user.username }),
      content: t('将同时删除其会话记录关联，操作不可撤销。'),
      okButtonProps: { danger: true },
      onOk: async () => {
        await http.delete(`/users/${user.id}`);
        message.success(t('已删除'));
        reload();
      },
    });
  };

  const createUser = async () => {
    const values = await form.validateFields();
    await http.post('/users', values);
    message.success(t('用户已创建'));
    setCreateOpen(false);
    form.resetFields();
    reload();
  };

  const columns: ProColumns<User>[] = [
    { title: t('用户名'), dataIndex: 'username', copyable: true },
    { title: t('姓名'), dataIndex: 'display_name' },
    {
      title: t('来源'),
      dataIndex: 'source',
      valueEnum: Object.fromEntries(
        Object.entries(SOURCE_TEXT).map(([k, v]) => [k, { text: v.text }]),
      ),
      render: (_, record) => (
        <Tag color={SOURCE_TEXT[record.source]?.color}>
          {SOURCE_TEXT[record.source]?.text ?? record.source}
        </Tag>
      ),
    },
    {
      title: t('状态'),
      dataIndex: 'status',
      valueEnum: {
        active: { text: t('启用'), status: 'Success' },
        disabled: { text: t('禁用'), status: 'Error' },
      },
    },
    {
      title: t('所属组'),
      dataIndex: 'groups',
      hideInSearch: true,
      render: (_, record) =>
        record.groups?.length
          ? record.groups.map((g) => (
              <Tag key={g.id} color="blue">
                {g.name}
              </Tag>
            ))
          : '-',
    },
    {
      title: t('最后登录'),
      dataIndex: 'last_login_at',
      hideInSearch: true,
      valueType: 'dateTime',
    },
    {
      title: t('操作'),
      valueType: 'option',
      render: (_, record) => (
        <Space>
          <a onClick={() => navigate(`/users/${record.id}`)}>{t('详情')}</a>
          <a onClick={() => toggleStatus(record)}>
            {record.status === 'active' ? t('禁用') : t('启用')}
          </a>
          <a
            onClick={async () => {
              await http.post(`/users/${record.id}/kick`);
              message.success(t('已强制下线'));
            }}
          >
            强制下线
          </a>
          <a
            onClick={async () => {
              const res = await http.post<never, { download_token: string }>(
                `/users/${record.id}/client-config`,
                {},
              );
              window.open(`/api/v1/client-config/${res.download_token}`, '_blank');
              message.success(t('配置已生成，浏览器开始下载（链接 5 分钟内单次有效）'));
            }}
          >
            下载配置
          </a>
          {record.source === 'local' && <a onClick={() => deleteUser(record)}>{t('删除')}</a>}
        </Space>
      ),
    },
  ];

  return (
    <PageContainer
      title={t('用户管理')}
      subTitle={t('IM 用户（钉钉/企微/飞书/LDAP）在首次扫码登录时自动建档；本地用户在此手工创建')}
    >
      <ProTable<User>
        rowKey="id"
        actionRef={actionRef}
        columns={columns}
        cardBordered
        search={{ labelWidth: 'auto' }}
        request={async (params) => {
          const data = await http.get<never, PageData<User>>('/users', {
            params: {
              page: params.current,
              pageSize: params.pageSize,
              keyword: params.username,
              source: params.source,
              status: params.status,
            },
          });
          return { data: data.list, total: data.total, success: true };
        }}
        toolBarRender={() => [
          <Button key="create" type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
            新建本地用户
          </Button>,
        ]}
        pagination={{ defaultPageSize: 20, showSizeChanger: true }}
      />
      <Modal
        title={t('新建本地用户')}
        open={createOpen}
        onOk={createUser}
        onCancel={() => setCreateOpen(false)}
        okText={t('创建')}
        destroyOnClose
      >
        <Form form={form} layout="vertical" initialValues={{ device_quota: 3 }}>
          <Form.Item
            name="username"
            label={t('用户名')}
            rules={[
              { required: true, message: t('必填') },
              { pattern: /^[\w.-]+$/, message: t('仅限字母数字._-') },
            ]}
          >
            <Input placeholder={t('登录用户名')} />
          </Form.Item>
          <Form.Item name="display_name" label={t('姓名')}>
            <Input placeholder={t('显示名（可空）')} />
          </Form.Item>
          <Form.Item name="email" label={t('邮箱')}>
            <Input placeholder={t('可空')} />
          </Form.Item>
          <Form.Item
            name="password"
            label={t('初始密码')}
            rules={[{ required: true, message: t('本地账号必须设置密码') }]}
          >
            <Input.Password placeholder={t('用于本地登录表单认证')} />
          </Form.Item>
        </Form>
      </Modal>
    </PageContainer>
  );
}
