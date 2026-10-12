import { PageContainer } from '@ant-design/pro-components';
import { t } from '../../i18n';
import { ProTable, type ProColumns, type ActionType } from '@ant-design/pro-components';
import {
  Alert,
  App,
  Button,
  Col,
  Form,
  Input,
  List,
  Modal,
  Row,
  Select,
  Space,
  Tag,
} from 'antd';
import { PlusOutlined, TeamOutlined, UserOutlined } from '@ant-design/icons';
import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import http, { type PageData } from '../../api/client';
import type { User, IdpSource } from '../../api/types';

/** 用户与组织（合并模块）：左侧组（含"全部用户"）+ 右侧所选视图。
 *  全部用户视图 = 原"用户管理"；组视图 = 原"组织管理"（成员/绑资源/导入）。 */

const SOURCE_TEXT: Record<IdpSource, { text: string; color: string }> = {
  local: { text: t('本地'), color: 'default' },
  ldap: { text: 'OpenLDAP', color: 'blue' },
  'ldap-ad': { text: 'AD', color: 'geekblue' },
  dingtalk: { text: t('钉钉'), color: 'processing' },
  wecom: { text: t('企业微信'), color: 'success' },
  feishu: { text: t('飞书'), color: 'purple' },
};

interface GroupRow {
  id: number;
  name: string;
  idp_ref: string;
  member_count: number;
  resource_count: number;
}

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

export default function Organization() {
  const navigate = useNavigate();
  const actionRef = useRef<ActionType>(null);
  const { message, modal } = App.useApp();

  const [groups, setGroups] = useState<GroupRow[]>([]);
  const [selected, setSelected] = useState<number | 'all'>('all');
  const [groupForm] = Form.useForm();
  const [userForm] = Form.useForm();
  const [groupOpen, setGroupOpen] = useState(false);
  const [userOpen, setUserOpen] = useState(false);

  // 成员管理（组视图）：管理成员弹窗（预选当前成员，保存=差分提交）
  const [memberOpen, setMemberOpen] = useState(false);
  const [addUserIds, setAddUserIds] = useState<number[]>([]);
  const [allUsers, setAllUsers] = useState<User[]>([]);
  const [allUsersTotal, setAllUsersTotal] = useState(0);

  // 绑定资源
  const [resOpen, setResOpen] = useState(false);
  const [allResources, setAllResources] = useState<{ id: number; name: string; cidr: string }[]>([]);
  const [resIds, setResIds] = useState<number[]>([]);
  const [resCurIds, setResCurIds] = useState<number[]>([]);
  const [memberIds, setMemberIds] = useState<number[]>([]);

  // 通讯录导入
  const [dirOpen, setDirOpen] = useState(false);
  const [dirIdp, setDirIdp] = useState('dingtalk');
  const [dirBusy, setDirBusy] = useState(false);
  const [dirResult, setDirResult] = useState<{ preview?: DirectoryPreview; synced?: DirectorySynced; error?: string }>({});

  const curGroup = selected === 'all' ? null : groups.find((g) => g.id === selected) || null;

  const reload = () => actionRef.current?.reload();
  const loadGroups = () => {
    http
      .get<never, PageData<GroupRow>>('/groups', { params: { page: 1, pageSize: 100 } })
      .then((d) => setGroups(d.list))
      .catch(() => {});
  };
  useEffect(() => {
    loadGroups();
    // 全量用户：仅供「管理成员」弹窗的勾选项使用（服务端单页上限 100，翻页取全）
    (async () => {
      const pageSize = 100;
      const first = await http.get<never, PageData<User>>('/users', {
        params: { page: 1, pageSize },
      });
      const all = [...first.list];
      setAllUsersTotal(first.total);
      const pages = Math.ceil(first.total / pageSize);
      for (let p = 2; p <= pages; p += 1) {
        // eslint-disable-next-line no-await-in-loop
        const next = await http.get<never, PageData<User>>('/users', {
          params: { page: p, pageSize },
        });
        all.push(...next.list);
      }
      setAllUsers(all);
    })().catch(() => {});
  }, []);

  // 选中具体组时拉取成员 id 集（「管理成员」弹窗勾选差分用；右侧表格走后端 groupId 分页）
  useEffect(() => {
    if (typeof selected !== 'number') return;
    let cancelled = false;
    http
      .get<never, { members: { id: number; name: string }[] }>(`/groups/${selected}`)
      .then((d) => {
        if (!cancelled) setMemberIds((d.members || []).map((m) => m.id));
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [selected]);

  /* ── 全部用户视图动作（原用户管理）── */
  const toggleStatus = (user: User) => {
    const action = user.status === 'active' ? t('禁用') : t('启用');
    modal.confirm({
      title: t('确认{v0}用户「{v1}」？', { v0: action, v1: user.display_name || user.username }),
      content: user.status === 'active' ? t('禁用会立即断开该用户全部在线会话，且后续认证被拒绝。') : undefined,
      onOk: async () => {
        await http.post(`/users/${user.id}/status`, { action: user.status === 'active' ? 'disable' : 'enable' });
        message.success(t('{v0}成功', { v0: action }));
        reload();
      },
    });
  };

  const createUser = async () => {
    const values = await userForm.validateFields();
    await http.post('/users', values);
    message.success(t('用户已创建'));
    setUserOpen(false);
    userForm.resetFields();
    reload();
  };

  /* ── 组动作（原组织管理）── */
  const createGroup = async () => {
    const values = await groupForm.validateFields();
    await http.post('/groups', values);
    message.success(t('组已创建'));
    setGroupOpen(false);
    groupForm.resetFields();
    loadGroups();
  };

  const deleteGroup = (g: GroupRow) => {
    modal.confirm({
      title: t('确认删除组「{v0}」？', { v0: g.name }),
      content: t('组内仍有成员时会被拒绝。'),
      okButtonProps: { danger: true },
      onOk: async () => {
        await http.delete(`/groups/${g.id}`);
        message.success(t('已删除'));
        setSelected('all');
        loadGroups();
      },
    });
  };

  const openMembers = async (g: GroupRow) => {
    setSelected(g.id);
    // 预选当前成员（差分基线），全量用户作为勾选项
    try {
      const d = await http.get<never, { members: { id: number; name: string }[] }>(`/groups/${g.id}`);
      const ids = (d.members || []).map((m) => m.id);
      setMemberIds(ids);
      setAddUserIds(ids);
      if (!allUsers.length) {
        const pageSize = 100;
        const first = await http.get<never, PageData<User>>('/users', { params: { page: 1, pageSize } });
        const all = [...first.list];
        const pages = Math.ceil(first.total / pageSize);
        for (let p = 2; p <= pages; p += 1) {
          // eslint-disable-next-line no-await-in-loop
          const next = await http.get<never, PageData<User>>('/users', { params: { page: p, pageSize } });
          all.push(...next.list);
        }
        setAllUsers(all);
      }
      setMemberOpen(true);
    } catch {
      message.error(t('成员读取失败'));
    }
  };

  const saveMembers = async () => {
    if (!curGroup) return;
    const add = addUserIds.filter((id) => !memberIds.includes(id));
    const remove = memberIds.filter((id) => !addUserIds.includes(id));
    await http.post(`/groups/${curGroup.id}/members`, { add, remove });
    message.success(t('组成员已更新（CCD 已自动重同步）'));
    setMemberIds(addUserIds);
    setMemberOpen(false);
    loadGroups();
    reload();
  };

  const openResources = async (g: GroupRow) => {
    setSelected(g.id);
    const d = await http.get<never, { resource_ids?: number[] }>(`/groups/${g.id}`);
    const rd = await http.get<never, PageData<{ id: number; name: string; cidr: string }>>('/resources', {
      params: { page: 1, pageSize: 100 },
    });
    setAllResources(rd.list);
    setResIds(d.resource_ids ?? []);
    setResCurIds(d.resource_ids ?? []);
    setResOpen(true);
  };

  const saveResources = async () => {
    if (!curGroup) return;
    await http.post(`/groups/${curGroup.id}/resources`, {
      add: resIds.filter((id) => !resCurIds.includes(id)),
      remove: resCurIds.filter((id) => !resIds.includes(id)),
    });
    message.success(t('资源绑定已更新（CCD 已自动重同步）'));
    setResOpen(false);
    loadGroups();
  };

  /* ── 通讯录导入（§23）── */
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
      loadGroups();
      reload();
    } catch (e) {
      setDirResult({ error: (e as Error).message || t('同步失败') });
    } finally {
      setDirBusy(false);
    }
  };

  /* ── 用户列（全部用户视图）── */
  const userColumns: ProColumns<User>[] = [
    { title: t('用户名'), dataIndex: 'username', copyable: true },
    { title: t('姓名'), dataIndex: 'display_name' },
    {
      title: t('来源'),
      dataIndex: 'source',
      valueEnum: Object.fromEntries(Object.entries(SOURCE_TEXT).map(([k, v]) => [k, { text: v.text }])),
      render: (_, record) => <Tag color={SOURCE_TEXT[record.source]?.color}>{SOURCE_TEXT[record.source]?.text ?? record.source}</Tag>,
    },
    {
      title: t('状态'),
      dataIndex: 'status',
      valueEnum: { active: { text: t('启用'), status: 'Success' }, disabled: { text: t('禁用'), status: 'Error' } },
    },
    {
      title: t('所属组'),
      dataIndex: 'groups',
      hideInSearch: true,
      render: (_, record) =>
        record.groups?.length ? record.groups.map((g) => <Tag key={g.id} color="blue">{g.name}</Tag>) : '-',
    },
    { title: t('最后登录'), dataIndex: 'last_login_at', hideInSearch: true, valueType: 'dateTime' },
    {
      title: t('操作'),
      valueType: 'option',
      render: (_, record) => (
        <Space>
          <a onClick={() => navigate(`/users/${record.id}`)}>{t('详情')}</a>
          <a onClick={() => toggleStatus(record)}>{record.status === 'active' ? t('禁用') : t('启用')}</a>
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
              const res = await http.post<never, { download_token: string }>(`/users/${record.id}/client-config`, {});
              window.open(`/api/v1/client-config/${res.download_token}`, '_blank');
              message.success(t('配置已生成，浏览器开始下载（5 分钟内单次有效）'));
            }}
          >
            下载配置
          </a>
          {record.source === 'local' && (
            <a
              onClick={() =>
                modal.confirm({
                  title: t('确认删除用户「{v0}」？', { v0: record.display_name || record.username }),
                  content: t('将同时删除其会话记录关联，操作不可撤销。'),
                  okButtonProps: { danger: true },
                  onOk: async () => {
                    await http.delete(`/users/${record.id}`);
                    message.success(t('已删除'));
                    reload();
                  },
                })
              }
            >
              删除
            </a>
          )}
        </Space>
      ),
    },
  ];

  /* ── 成员列（组视图）── */
  const memberColumns: ProColumns<User>[] = [
    { title: t('用户名'), dataIndex: 'username' },
    { title: t('姓名'), dataIndex: 'display_name' },
    {
      title: t('来源'),
      dataIndex: 'source',
      render: (_, record) => <Tag color={SOURCE_TEXT[record.source]?.color}>{SOURCE_TEXT[record.source]?.text ?? record.source}</Tag>,
    },
    { title: t('状态'), dataIndex: 'status', hideInSearch: true, render: (_, r) => (r.status === 'active' ? <Tag color="green">{t('启用')}</Tag> : <Tag color="red">{t('禁用')}</Tag>) },
  ];

  const viewAll = selected === 'all';
  // 两个视图都由后端分页：全部=/users；组视图=/users?groupId=（成员 20/页）
  const tableRequest = viewAll
    ? async (params: Record<string, unknown>) => {
        const data = await http.get<never, PageData<User>>('/users', {
          params: { page: params.current, pageSize: params.pageSize, keyword: params.username, source: params.source, status: params.status },
        });
        return { data: data.list, total: data.total, success: true };
      }
    : async (params: Record<string, unknown>) => {
        // gid 由 ProTable params 注入（selected 变化 → params 变化 → 自动重新请求）
        const gid = typeof params.gid === 'number' && params.gid > 0 ? params.gid : selected;
        if (typeof gid !== 'number') return { data: [], total: 0, success: true };
        const data = await http.get<never, PageData<User>>('/users', {
          params: {
            groupId: gid,
            page: params.current,
            pageSize: params.pageSize,
            keyword: params.username,
            status: params.status,
          },
        });
        return { data: data.list, total: data.total, success: true };
      };

  return (
    <PageContainer
      title={t('用户与组织')}
      subTitle={t('用户、部门（组）与权限分配统一管理；通讯录导入的部门在此绑定资源')}
    >
      {curGroup?.idp_ref && (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 12 }}
          message={`「${curGroup.name}」是通讯录同步组：同源成员（${curGroup.idp_ref.split(':')[0]}）按目录自动对齐；手工加入的本地/门户账号会永久保留，不会因同步被移除`}
        />
      )}
      <Row gutter={16}>
        <Col xs={24} md={7} lg={6}>
          <div style={{ background: '#fff', border: '1px solid #e0e0e0', borderRadius: 14, overflow: 'hidden' }}>
            <div style={{ padding: '14px 16px 6px', fontWeight: 600 }}>{t('组织 / 分组')}</div>
            <div style={{ maxHeight: 560, overflowY: 'auto', padding: 8 }}>
              <List
                size="small"
                dataSource={[{ id: -1, name: t('全部用户'), idp_ref: '', member_count: allUsersTotal, resource_count: 0 } as GroupRow, ...groups]}
                renderItem={(g) => {
                  const id = g.id === -1 ? 'all' : g.id;
                  const on = selected === id;
                  return (
                    <List.Item
                      style={{
                        cursor: 'pointer',
                        padding: '9px 12px',
                        borderRadius: 10,
                        background: on ? '#e6f4ff' : undefined,
                        marginBottom: 2,
                      }}
                      onClick={() => setSelected(id)}
                    >
                      <Space>
                        {id === 'all' ? <UserOutlined style={{ color: '#0066cc' }} /> : <TeamOutlined />}
                        <span style={{ fontWeight: on ? 600 : 400 }}>{g.name}</span>
                      </Space>
                      <span style={{ color: '#999', fontSize: 12 }}>{g.member_count} 人</span>
                    </List.Item>
                  );
                }}
              />
            </div>
            <div style={{ padding: 10, borderTop: '1px solid #f0f0f0', display: 'flex', gap: 8 }}>
              <Button size="small" icon={<PlusOutlined />} onClick={() => setGroupOpen(true)}>
                新建组
              </Button>
              <Button size="small" type="primary" ghost onClick={() => { setDirResult({}); setDirOpen(true); }}>
                通讯录导入
              </Button>
            </div>
          </div>
        </Col>
        <Col xs={24} md={17} lg={18}>
          {viewAll ? null : curGroup ? (
            <div style={{ marginBottom: 12, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <Button
                icon={<PlusOutlined />}
                onClick={() => openMembers(curGroup)}
              >
                管理成员
              </Button>
              <Button icon={<PlusOutlined />} onClick={() => openResources(curGroup)}>
                绑定资源
              </Button>
              <Button danger onClick={() => deleteGroup(curGroup)}>
                删除组
              </Button>
              <span style={{ color: '#888', alignSelf: 'center', fontSize: 13 }}>
                {curGroup.resource_count} 个资源 · {curGroup.member_count} 名成员
              </span>
            </div>
          ) : null}

          <ProTable<User>
            rowKey="id"
            actionRef={actionRef}
            columns={viewAll ? userColumns : memberColumns}
            cardBordered
            search={viewAll ? { labelWidth: 'auto' } : false}
            request={tableRequest}
            params={{ gid: typeof selected === 'number' ? selected : 0 }}
            polling={viewAll ? undefined : 30000}
            toolBarRender={() =>
              viewAll
                ? [
                    <Button key="u" type="primary" icon={<PlusOutlined />} onClick={() => setUserOpen(true)}>
                      新建本地用户
                    </Button>,
                  ]
                : []
            }
            pagination={{ defaultPageSize: 20, showSizeChanger: viewAll }}
          />
        </Col>
      </Row>

      {/* 新建组 */}
      <Modal title={t('新建组')} open={groupOpen} onOk={createGroup} onCancel={() => setGroupOpen(false)} okText={t('创建')} destroyOnClose>
        <Form form={groupForm} layout="vertical">
          <Form.Item name="name" label={t('组名')} rules={[{ required: true, message: '必填' }]}>
            <Input placeholder={t('如：财务部')} />
          </Form.Item>
        </Form>
      </Modal>

      {/* 管理成员：预选当前成员，勾选/取消后保存=差分提交 */}
      <Modal
        title={t('管理「{v0}」成员', { v0: curGroup?.name ?? '' })}
        open={memberOpen}
        onOk={saveMembers}
        onCancel={() => setMemberOpen(false)}
        okText={t('保存成员')}
        cancelText={t('取消')}
        confirmLoading={false}
        destroyOnClose
        width={480}
      >
        <p style={{ color: '#888', fontSize: 13, marginTop: 0 }}>
          勾选 = 加入本组；取消勾选 = 移出本组（通讯录同步组的同源成员仍按目录自动对齐）
        </p>
        <Select
          mode="multiple"
          style={{ width: '100%' }}
          placeholder={t('选择成员')}
          value={addUserIds}
          onChange={setAddUserIds}
          options={allUsers.map((u) => ({ value: u.id, label: `${u.display_name || u.username}（${u.username}）` }))}
        />
      </Modal>

      {/* 新建本地用户 */}
      <Modal title={t('新建本地用户')} open={userOpen} onOk={createUser} onCancel={() => setUserOpen(false)} okText={t('创建')} destroyOnClose>
        <Form form={userForm} layout="vertical">
          <Form.Item name="username" label={t('用户名')} rules={[{ required: true, message: '必填' }, { pattern: /^[\w.-]+$/, message: '仅限字母数字._-' }]}>
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
            rules={[
              { required: true, message: t('本地账号必须设置密码') },
              { min: 8, message: t('密码长度不能少于 8 位') },
            ]}
          >
            <Input.Password placeholder={t('用于本地登录表单认证（至少 8 位）')} />
          </Form.Item>
        </Form>
      </Modal>

      {/* 绑定资源 */}
      <Modal title={`为「${curGroup?.name}」绑定资源`} open={resOpen} onOk={saveResources} onCancel={() => setResOpen(false)} okText={t('保存')} destroyOnClose>
        <p style={{ color: '#888', fontSize: 13, marginBottom: 8 }}>{t('勾选网段资源，该组成员即可访问（CCD 自动重同步）')}</p>
        <Select
          mode="multiple"
          style={{ width: '100%' }}
          placeholder={t('选择资源')}
          value={resIds}
          onChange={setResIds}
          options={allResources.map((r) => ({ value: r.id, label: `${r.name}（${r.cidr}）` }))}
        />
      </Modal>

      {/* 通讯录导入 */}
      <Modal title={t('从企业通讯录导入（目录同步）')} open={dirOpen} onCancel={() => setDirOpen(false)} footer={null} width={620}>
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
            description={t('通讯录部门将同步为组（组成员与通讯录对齐）；导入后选中组绑定资源即为该部门分配访问权限；通讯录中移除的用户会被自动禁用（无法连接，手动禁用的用户不会被重新启用）。')}
          />
          {dirResult.error && <Alert type="error" showIcon message={t('通讯录拉取失败')} description={dirResult.error} />}
          {dirResult.preview && (
            <div>
              <p style={{ margin: '4px 0' }}>
                通讯录共 <b>{dirResult.preview.directory_users}</b> 人 / {dirResult.preview.directory_departments} 个部门：新建{' '}
                {dirResult.preview.diff.new_users.length} 人、更新 {dirResult.preview.diff.update_users.length} 人、将禁用{' '}
                {dirResult.preview.diff.disable_users.length} 人、新建组 {dirResult.preview.diff.new_groups.length} 个
              </p>
              {dirResult.preview.diff.new_users.length > 0 && (
                <p style={{ margin: '4px 0', fontSize: 12, color: '#888' }}>
                  新用户：{dirResult.preview.diff.new_users.slice(0, 20).join('、')}
                  {dirResult.preview.diff.new_users.length > 20 ? ' …' : ''}
                </p>
              )}
              {dirResult.preview.diff.new_groups.length > 0 && (
                <p style={{ margin: '4px 0', fontSize: 12, color: '#888' }}>新组：{dirResult.preview.diff.new_groups.join('、')}</p>
              )}
              {dirResult.preview.diff.disable_users.length > 0 && (
                <p style={{ margin: '4px 0', fontSize: 12, color: '#c00' }}>将禁用：{dirResult.preview.diff.disable_users.join('、')}</p>
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
