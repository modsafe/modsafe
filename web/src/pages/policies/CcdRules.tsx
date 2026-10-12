import { PageContainer } from '@ant-design/pro-components';
import { t } from '../../i18n';
import { ProTable, type ProColumns, type ActionType } from '@ant-design/pro-components';
import { Button, Tag, App, Form, Input, Modal, Select, InputNumber, Switch, Descriptions, Alert, Space } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { useEffect, useRef, useState } from 'react';
import http, { type PageData } from '../../api/client';
import type { CcdRule, User, Group } from '../../api/types';

const TYPE_TEXT: Record<CcdRule['type'], string> = {
  route: t('路由下发'),
  dns: t('DNS 推送'),
  redirect_gateway: t('全局代理'),
  iroute: t('子网通告'),
  route_metric: t('路由度量'),
};

const SCOPE_TEXT: Record<CcdRule['scope'], { text: string; color: string }> = {
  global: { text: t('全局'), color: 'default' },
  group: { text: t('组级'), color: 'blue' },
  user: { text: t('用户级'), color: 'orange' },
};

interface PreviewResult {
  layers: {
    global: CcdRule[];
    groups: { group: string; rules: CcdRule[] }[];
    user: CcdRule[] | null;
  };
  effective: { routes: string[]; dns: string[]; redirect_gateway: boolean; truncated: boolean };
  ccd_content: string;
  warnings: string[];
}

export default function CcdRules() {
  const actionRef = useRef<ActionType>(null);
  const { message, modal } = App.useApp();
  const [editOpen, setEditOpen] = useState(false);
  const [editing, setEditing] = useState<CcdRule | null>(null);
  const [form] = Form.useForm();
  const [scope, setScope] = useState<'global' | 'group' | 'user'>('global');
  const [groups, setGroups] = useState<Group[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [previewFor, setPreviewFor] = useState<User | null>(null);
  const [preview, setPreview] = useState<PreviewResult | null>(null);

  useEffect(() => {
    http.get<never, PageData<Group>>('/groups', { params: { page: 1, pageSize: 100 } })
      .then((d) => setGroups(d.list)).catch(() => {});
    http.get<never, PageData<User>>('/users', { params: { page: 1, pageSize: 100 } })
      .then((d) => setUsers(d.list)).catch(() => {});
  }, []);

  const reload = () => actionRef.current?.reload();

  const openCreate = () => {
    setEditing(null);
    setScope('global');
    form.resetFields();
    form.setFieldsValue({ type: 'route', priority: 0, enabled: true });
    setEditOpen(true);
  };

  const openEdit = (rule: CcdRule) => {
    setEditing(rule);
    setScope(rule.scope);
    form.setFieldsValue({
      name: rule.name, type: rule.type, value: rule.value,
      priority: rule.priority, group_id: rule.group_id ?? undefined,
      user_id: rule.user_id ?? undefined, enabled: rule.enabled,
    });
    setEditOpen(true);
  };

  const saveRule = async () => {
    const values = await form.validateFields();
    const body = {
      name: values.name, type: values.type, value: values.value,
      priority: values.priority ?? 0, enabled: values.enabled ?? true,
      group_id: scope === 'group' ? values.group_id : null,
      user_id: scope === 'user' ? values.user_id : null,
    };
    if (editing) {
      await http.put(`/ccd/rules/${editing.id}`, body);
      message.success(t('规则已更新并同步下发'));
    } else {
      await http.post('/ccd/rules', body);
      message.success(t('规则已创建并同步下发'));
    }
    setEditOpen(false);
    reload();
  };

  const deleteRule = (rule: CcdRule) => {
    modal.confirm({
      title: t('确认删除规则「{v0}」？', { v0: rule.name }),
      content: t('下发文件将自动重新同步。'),
      okButtonProps: { danger: true },
      onOk: async () => {
        await http.delete(`/ccd/rules/${rule.id}`);
        message.success(t('已删除'));
        reload();
      },
    });
  };

  const openPreview = async (user: User) => {
    setPreviewFor(user);
    setPreview(null);
    const res = await http.post<never, PreviewResult>('/ccd/preview', { user_id: user.id });
    setPreview(res);
  };

  const applyChanges = () => {
    modal.confirm({
      title: t('应用变更（对全部在线用户踢线重连）'),
      content: t('规则已即时保存；踢线后客户端自动重连并获取新路由，踢线窗口期间新认证短暂失败。确认执行？'),
      okText: t('确认踢线'),
      onOk: async () => {
        const res = await http.post<never, { results: unknown[]; notice: string }>('/ccd/apply', {});
        message.success(res.notice);
        reload();
      },
    });
  };

  const columns: ProColumns<CcdRule>[] = [
    { title: t('规则名称'), dataIndex: 'name' },
    {
      title: t('类型'),
      dataIndex: 'type',
      valueEnum: Object.fromEntries(Object.entries(TYPE_TEXT).map(([k, v]) => [k, { text: v }])),
    },
    { title: t('值'), dataIndex: 'value', copyable: true },
    {
      title: t('层级'),
      dataIndex: 'scope',
      valueEnum: Object.fromEntries(Object.entries(SCOPE_TEXT).map(([k, v]) => [k, { text: v.text }])),
      render: (_, record) => (
        <Tag color={SCOPE_TEXT[record.scope]?.color}>{SCOPE_TEXT[record.scope]?.text}</Tag>
      ),
    },
    { title: t('绑定对象'), dataIndex: 'bind_name', hideInSearch: true },
    { title: t('优先级'), dataIndex: 'priority', hideInSearch: true, sorter: true },
    {
      title: t('状态'),
      dataIndex: 'enabled',
      hideInSearch: true,
      valueEnum: {
        true: { text: t('启用'), status: 'Success' },
        false: { text: t('停用'), status: 'Default' },
      },
    },
    { title: t('更新时间'), dataIndex: 'updated_at', hideInSearch: true, valueType: 'dateTime' },
    {
      title: t('操作'),
      valueType: 'option',
      render: (_, record) => (
        <Space>
          <a onClick={() => openEdit(record)}>{t('编辑')}</a>
          <a onClick={() => deleteRule(record)}>{t('删除')}</a>
        </Space>
      ),
    },
  ];

  return (
    <PageContainer
      title={t('策略管理 (CCD)')}
      subTitle={t('三层合并模型：全局 < 组 < 用户（§14）；保存即自动同步下发文件；冲突检测阻断重复')}
    >
      <ProTable<CcdRule>
        rowKey="id"
        actionRef={actionRef}
        columns={columns}
        cardBordered
        search={{ labelWidth: 'auto' }}
        request={async (params) => {
          const data = await http.get<never, PageData<CcdRule>>('/ccd/rules', {
            params: {
              page: params.current,
              pageSize: params.pageSize,
              type: params.type,
              scope: params.scope,
            },
          });
          return { data: data.list, total: data.total, success: true };
        }}
        toolBarRender={() => [
          <Select
            key="preview-user"
            showSearch
            optionFilterProp="label"
            style={{ width: 220 }}
            placeholder={t('选择用户模拟预览…')}
            value={previewFor?.id}
            onChange={(uid: number) => {
              const u = users.find((x) => x.id === uid);
              if (u) openPreview(u);
            }}
            options={users.map((u) => ({
              value: u.id,
              label: `${u.display_name || u.username} (${u.username})`,
            }))}
          />,
          <Button key="apply" type="primary" ghost onClick={applyChanges}>
            应用变更（重连生效）
          </Button>,
          <Button key="create" type="primary" icon={<PlusOutlined />} onClick={openCreate}>
            新建规则
          </Button>,
        ]}
        pagination={{ defaultPageSize: 20 }}
      />

      {/* 新建/编辑规则 */}
      <Modal
        title={editing ? `编辑规则 #${editing.id}` : t('新建规则')}
        open={editOpen}
        onOk={saveRule}
        onCancel={() => setEditOpen(false)}
        okText={t('保存')}
        width={560}
        destroyOnClose
      >
        <Form form={form} layout="vertical">
          <Form.Item name="name" label={t('规则名称')} rules={[{ required: true, message: '必填' }]}>
            <Input placeholder={t('如：财务网段')} />
          </Form.Item>
          <Space style={{ display: 'flex' }}>
            <Form.Item name="type" label={t('类型')} rules={[{ required: true }]} style={{ minWidth: 160 }}>
              <Select
                options={Object.entries(TYPE_TEXT).map(([k, v]) => ({ value: k, label: v }))}
                onChange={() => {/* route 类型时 value 需为 CIDR，由服务端校验 */}}
              />
            </Form.Item>
            <Form.Item name="priority" label={t('优先级')} style={{ minWidth: 120 }}>
              <InputNumber min={0} max={9999} />
            </Form.Item>
            <Form.Item name="enabled" label={t('启用')} valuePropName="checked">
              <Switch />
            </Form.Item>
          </Space>
          <Form.Item
            name="value"
            label={t('值')}
            rules={[{ required: true, message: t('必填') }]}
            extra={t('route/iroute 需 CIDR（如 10.0.1.0/24）；dns 填 IP；redirect_gateway 填 true/false；route_metric 填数字')}
          >
            <Input />
          </Form.Item>
          <Form.Item label={t('绑定层级')} required>
            <Select
              value={scope}
              onChange={(v) => setScope(v)}
              options={[
                { value: 'global', label: t('全局（所有用户）') },
                { value: 'group', label: t('组级') },
                { value: 'user', label: t('用户级（覆盖组）') },
              ]}
            />
          </Form.Item>
          {scope === 'group' && (
            <Form.Item name="group_id" label={t('选择组')} rules={[{ required: true, message: '必选' }]}>
              <Select
                showSearch
                optionFilterProp="label"
                options={groups.map((g) => ({ value: g.id, label: g.name }))}
                placeholder={t('选择组')}
              />
            </Form.Item>
          )}
          {scope === 'user' && (
            <Form.Item name="user_id" label={t('选择用户')} rules={[{ required: true, message: '必选' }]}>
              <Select
                showSearch
                optionFilterProp="label"
                options={users.map((u) => ({
                  value: u.id,
                  label: `${u.display_name || u.username} (${u.username})`,
                }))}
                placeholder={t('选择用户')}
              />
            </Form.Item>
          )}
        </Form>
      </Modal>

      {/* 模拟预览 */}
      <Modal
        title={t('模拟预览 — {v0}', { v0: previewFor?.display_name || previewFor?.username || '' })}
        open={!!previewFor}
        onCancel={() => setPreviewFor(null)}
        footer={null}
        width={720}
      >
        {preview ? (
          <>
            {preview.warnings.map((w) => (
              <Alert key={w} type="warning" message={w} style={{ marginBottom: 8 }} />
            ))}
            <Descriptions column={1} size="small" bordered style={{ marginBottom: 12 }}>
              <Descriptions.Item label={t('生效路由')}>
                {preview.effective.routes.join(', ') || t('（无）')}
              </Descriptions.Item>
              <Descriptions.Item label="DNS">
                {preview.effective.dns.join(', ') || t('（无）')}
              </Descriptions.Item>
              <Descriptions.Item label={t('全局代理')}>
                {preview.effective.redirect_gateway ? t('是') : t('否')}
              </Descriptions.Item>
            </Descriptions>
            <Alert
              type="info"
              message={t('三层命中明细')}
              description={
                <div style={{ fontSize: 12 }}>
                  <div>全局：{preview.layers.global.length} 条</div>
                  {preview.layers.groups.map((g) => (
                    <div key={g.group}>组[{g.group}]：{g.rules.length} 条</div>
                  ))}
                  <div>用户级：{preview.layers.user?.length ?? 0} 条</div>
                </div>
              }
              style={{ marginBottom: 12 }}
            />
            <pre
              style={{
                background: '#0b1021', color: '#7fdbca', padding: 12,
                borderRadius: 6, fontSize: 12, whiteSpace: 'pre-wrap',
              }}
            >
              {preview.ccd_content || t('（空 — 该用户无任何命中规则，连接后仅可达网关）')}
            </pre>
          </>
        ) : (
          <Alert type="info" message={t('加载中…')} />
        )}
      </Modal>
    </PageContainer>
  );
}
