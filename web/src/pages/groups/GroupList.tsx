import { PageContainer } from '@ant-design/pro-components';
import { t } from '../../i18n';
import { ProTable, type ProColumns, type ActionType } from '@ant-design/pro-components';
import { Alert, Button, Space, App, Form, Input, Modal, Select, Tag } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { useRef, useState, useEffect } from 'react';
import http, { type PageData } from '../../api/client';
import type { Group, User } from '../../api/types';

export default function GroupList() {
  const actionRef = useRef<ActionType>(null);
  const { message, modal } = App.useApp();
  const [createOpen, setCreateOpen] = useState(false);
  const [form] = Form.useForm();
  const [membersFor, setMembersFor] = useState<Group | null>(null);
  const [allUsers, setAllUsers] = useState<User[]>([]);
  const [allResources, setAllResources] = useState<{ id: number; name: string; cidr: string }[]>([]);
  const [groupDetail, setGroupDetail] = useState<(Group & {
    members: { id: number; name: string }[];
    resource_ids: number[];
  }) | null>(null);
  const [addUserIds, setAddUserIds] = useState<number[]>([]);
  const [removeIds, setRemoveIds] = useState<number[]>([]);
  const [resIds, setResIds] = useState<number[]>([]);

  const reload = () => actionRef.current?.reload();

  // 成员弹窗打开时拉全量用户/资源 + 组详情（成员列表 + 已绑资源）
  useEffect(() => {
    if (!membersFor) return;
    http.get<never, PageData<User>>('/users', { params: { page: 1, pageSize: 100 } })
      .then((d) => setAllUsers(d.list))
      .catch(() => {});
    http.get<never, PageData<{ id: number; name: string; cidr: string }>>('/resources', { params: { page: 1, pageSize: 100 } })
      .then((d) => setAllResources(d.list))
      .catch(() => {});
    http.get<never, Group & { members?: { id: number; name: string }[]; resource_ids?: number[] }>(`/groups/${membersFor.id}`)
      .then((g) => {
        setGroupDetail({
          ...membersFor,
          members: g.members ?? [],
          resource_ids: g.resource_ids ?? [],
        });
      })
      .catch(() => setGroupDetail({ ...membersFor, members: [], resource_ids: [] }));
  }, [membersFor]);

  // §23 通讯录导入
  const [dirOpen, setDirOpen] = useState(false);
  const [dirIdp, setDirIdp] = useState('dingtalk');
  const [dirBusy, setDirBusy] = useState(false);
  const [dirResult, setDirResult] = useState<{ preview?: DirectoryPreview; synced?: DirectorySynced; error?: string }>({});

  const dirPreview = async () => {
    setDirBusy(true);
    setDirResult({});
    try {
      const d = await http.post<never, DirectoryPreview>('/directory/preview', { idp: dirIdp });
      setDirResult({ preview: d });
    } catch (e) {
      setDirResult({ error: (e as Error).message || t('拉取失败') });
    } finally {
      setDirBusy(false);
    }
  };

  const dirSync = async () => {
    setDirBusy(true);
    try {
      const d = await http.post<never, DirectorySynced>('/directory/sync', { idp: dirIdp });
      setDirResult({ synced: d });
      reload();
    } catch (e) {
      setDirResult({ error: (e as Error).message || t('同步失败') });
    } finally {
      setDirBusy(false);
    }
  };

  const createGroup = async () => {
    const values = await form.validateFields();
    await http.post('/groups', values);
    message.success(t('组已创建'));
    setCreateOpen(false);
    form.resetFields();
    reload();
  };

  const deleteGroup = (g: Group) => {
    modal.confirm({
      title: t('确认删除组「{v0}」？', { v0: g.name }),
      content: t('组内仍有成员时会被拒绝。'),
      okButtonProps: { danger: true },
      onOk: async () => {
        await http.delete(`/groups/${g.id}`);
        message.success(t('已删除'));
        reload();
      },
    });
  };

  const saveMembers = async () => {
    if (!membersFor) return;
    await http.post(`/groups/${membersFor.id}/members`, {
      add: addUserIds,
      remove: removeIds,
    });
    if (groupDetail) {
      // 资源绑定：Select 的值为完整集合，与已绑集合求差
      const cur = new Set(groupDetail.resource_ids);
      const add = resIds.filter((r) => !cur.has(r));
      const remove = groupDetail.resource_ids.filter((r) => !resIds.includes(r));
      if (add.length || remove.length) {
        await http.post(`/groups/${membersFor.id}/resources`, { add, remove });
      }
    }
    message.success(t('成员与资源绑定已更新（CCD 下发文件已自动重新同步）'));
    setAddUserIds([]);
    setRemoveIds([]);
    setResIds([]);
    setMembersFor(null);
    reload();
  };

  interface DirectoryDiff {
  new_users: string[];
  update_users: string[];
  disable_users: string[];
  new_groups: string[];
}
interface DirectoryPreview {
  idp: string;
  directory_users: number;
  directory_departments: number;
  diff: DirectoryDiff;
}
interface DirectorySynced {
  idp: string;
  created: number;
  updated: number;
  disabled: number;
  groups: number;
  members_bound: number;
  notice: string;
}

const columns: ProColumns<Group>[] = [
    { title: t('组名'), dataIndex: 'name' },
    { title: t('成员数'), dataIndex: 'member_count', hideInSearch: true },
    { title: t('绑定资源数'), dataIndex: 'resource_count', hideInSearch: true },
    { title: t('IdP 关联'), dataIndex: 'idp_ref', hideInSearch: true, render: (v) => v ? <Tag>{v as string}</Tag> : '-' },
    { title: t('创建时间'), dataIndex: 'created_at', hideInSearch: true, valueType: 'dateTime' },
    {
      title: t('操作'),
      valueType: 'option',
      render: (_, record) => (
        <Space>
          <a onClick={() => setMembersFor(record)}>{t('成员管理')}</a>
          <a onClick={() => deleteGroup(record)}>{t('删除')}</a>
        </Space>
      ),
    },
  ];

  return (
    <PageContainer title={t('组织管理')} subTitle={t('组绑定资源后，成员用户认证时自动下发对应路由（CCD）')}>
      <ProTable<Group>
        rowKey="id"
        actionRef={actionRef}
        columns={columns}
        cardBordered
        request={async (params) => {
          const data = await http.get<never, PageData<Group>>('/groups', {
            params: { page: params.current, pageSize: params.pageSize, keyword: params.name },
          });
          return { data: data.list, total: data.total, success: true };
        }}
        toolBarRender={() => [
          <Button key="dir" type="primary" ghost onClick={() => { setDirResult({}); setDirOpen(true); }}>
            从企业通讯录导入
          </Button>,
          <Button key="create" type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
            新建组
          </Button>,
        ]}
        pagination={{ defaultPageSize: 20 }}
      />

      <Modal
        title={t('新建组')}
        open={createOpen}
        onOk={createGroup}
        onCancel={() => setCreateOpen(false)}
        okText={t('创建')}
        destroyOnClose
      >
        <Form form={form} layout="vertical">
          <Form.Item name="name" label={t('组名')} rules={[{ required: true, message: '必填' }]}>
            <Input placeholder={t('如：研发部 / 财务部')} />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={t('成员管理 — {v0}', { v0: membersFor?.name ?? '' })}
        open={!!membersFor}
        onOk={saveMembers}
        onCancel={() => setMembersFor(null)}
        okText={t('保存变更')}
        width={520}
        destroyOnClose
      >
        <Form layout="vertical">
          <Form.Item label={t('添加成员（从全部用户中选择）')}>
            <Select
              mode="multiple"
              style={{ width: '100%' }}
              placeholder={t('选择要加入的用户')}
              value={addUserIds}
              onChange={setAddUserIds}
              optionFilterProp="label"
              options={allUsers.map((u) => ({
                value: u.id,
                label: `${u.display_name || u.username} (${u.username})`,
              }))}
            />
          </Form.Item>
          <Form.Item label={t('移除成员（选择要移除的成员）')}>
            <Select
              mode="multiple"
              style={{ width: '100%' }}
              placeholder={t('选择要移除的成员')}
              value={removeIds}
              onChange={setRemoveIds}
              options={(groupDetail?.members ?? []).map((m) => ({
                value: m.id,
                label: m.name,
              }))}
            />
          </Form.Item>
          <Form.Item label={t('绑定资源（成员认证时自动下发这些网段的路由）')}>
            <Select
              mode="multiple"
              style={{ width: '100%' }}
              placeholder={t('选择要绑定的资源')}
              value={groupDetail?.resource_ids ?? []}
              onChange={setResIds}
              optionFilterProp="label"
              options={allResources.map((r) => ({
                value: r.id,
                label: `${r.name} (${r.cidr})`,
              }))}
            />
          </Form.Item>
        </Form>
      </Modal>
      <Modal
        title={t('从企业通讯录导入（目录同步）')}
        open={dirOpen}
        onCancel={() => setDirOpen(false)}
        footer={null}
        width={620}
      >
        <Space direction="vertical" style={{ width: '100%' }} size={12}>
          <Space>
            <span>{t('认证源：')}</span>
            <Select
              value={dirIdp}
              style={{ width: 160 }}
              onChange={setDirIdp}
              options={[
                { value: 'dingtalk', label: t('钉钉') },
                { value: 'wecom', label: t('企业微信') },
                { value: 'feishu', label: t('飞书') },
              ]}
            />
            <Button type="primary" loading={dirBusy} onClick={dirPreview}>
              拉取预览（不落库）
            </Button>
          </Space>
          <Alert
            type="info"
            showIcon
            message={t('导入规则')}
            description={t('通讯录部门将同步为组（组成员与通讯录对齐）；导入后在此页为组绑定资源即为该部门分配访问权限；通讯录中移除的用户会被自动禁用（无法连接，手动禁用的用户不会被重新启用）。')}
          />
          {dirResult.error && <Alert type="error" showIcon message={t('通讯录拉取失败')} description={dirResult.error} />}
          {dirResult.preview && (
            <div>
              <p style={{ margin: '4px 0' }}>
                通讯录共 <b>{dirResult.preview.directory_users}</b> 人 / {dirResult.preview.directory_departments} 个部门：
                新建 {dirResult.preview.diff.new_users.length} 人、更新 {dirResult.preview.diff.update_users.length} 人、
                将禁用 {dirResult.preview.diff.disable_users.length} 人、新建组 {dirResult.preview.diff.new_groups.length} 个
              </p>
              {dirResult.preview.diff.new_users.length > 0 && (
                <p style={{ margin: '4px 0', fontSize: 12, color: '#888' }}>
                  新用户：{dirResult.preview.diff.new_users.slice(0, 20).join('、')}
                  {dirResult.preview.diff.new_users.length > 20 ? ' …' : ''}
                </p>
              )}
              {dirResult.preview.diff.new_groups.length > 0 && (
                <p style={{ margin: '4px 0', fontSize: 12, color: '#888' }}>
                  新组：{dirResult.preview.diff.new_groups.join('、')}
                </p>
              )}
              {dirResult.preview.diff.disable_users.length > 0 && (
                <p style={{ margin: '4px 0', fontSize: 12, color: '#c00' }}>
                  将禁用：{dirResult.preview.diff.disable_users.join('、')}
                </p>
              )}
              <Button type="primary" danger style={{ marginTop: 8 }} loading={dirBusy} onClick={dirSync}>
                确认导入（{dirResult.preview.diff.new_users.length + dirResult.preview.diff.update_users.length} 人）
              </Button>
            </div>
          )}
          {dirResult.synced && (
            <Alert
              type="success"
              showIcon
              message={t('导入完成：新建 {v0} 人 / 更新 {v1} 人 / 禁用 {v2} 人 / {v3} 个组', { v0: dirResult.synced.created, v1: dirResult.synced.updated, v2: dirResult.synced.disabled, v3: dirResult.synced.groups })}
              description={dirResult.synced.notice}
            />
          )}
        </Space>
      </Modal>
    </PageContainer>
  );
}
