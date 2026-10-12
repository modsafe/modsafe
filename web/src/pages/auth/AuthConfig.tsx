import { PageContainer } from '@ant-design/pro-components';
import { t } from '../../i18n';
import {
  Alert,
  App,
  Button,
  Card,
  Form,
  Input,
  Radio,
  Select,
  Space,
  Switch,
  Tag,
  Typography,
} from 'antd';
import { useEffect, useState } from 'react';
import http from '../../api/client';

interface AuthConfig {
  primary_idp: string;
  local_auth_enabled: boolean;
  hide_local_link: boolean;
  client_verify_policy: string;
  configured: Record<string, boolean>;
}
interface IdpCred {
  enabled: boolean;
  label: string;
  type: 'oauth' | 'ldap' | 'saml';
  fields: Record<string, string>;
  callback_url: string;
  acs_url?: string;
  metadata_url?: string;
}
interface CredsResp {
  idps: Record<string, IdpCred>;
}
interface SamlMetaParsed {
  entity_id: string;
  sso_url: string;
  idp_certificate: string;
  cert_not_after?: string;
}

const IDP_OPTIONS = [
  { value: 'dingtalk', label: t('钉钉扫码') },
  { value: 'wecom', label: t('企业微信扫码') },
  { value: 'feishu', label: t('飞书扫码') },
  { value: 'saml', label: t('企业 SSO（SAML 2.0）') },
  { value: 'ldap-ad', label: t('AD 域账号') },
  { value: 'openldap', label: 'OpenLDAP' },
];

const SECRET_HINT = t('留空或保持 ****** = 不修改已保存的密钥');

const LDAP_FIELDS = [
  { key: 'label', label: t('登录页显示名'), placeholder: t('如：AD 域账号') },
  { key: 'server', label: t('服务器地址'), placeholder: 'ldap://dc01.corp.com:389' },
  { key: 'bind_dn', label: t('服务账号 DN'), placeholder: 'svc-modsec@corp.example.com' },
  { key: 'bind_password', label: t('服务账号密码'), secret: true },
  { key: 'base_dn', label: t('用户搜索 Base DN'), placeholder: 'dc=corp,dc=example,dc=com' },
  { key: 'user_filter', label: t('用户过滤器'), placeholder: '(sAMAccountName={username})' },
];

const SAML_FIELDS = [
  { key: 'label', label: t('登录页显示名'), placeholder: t('如：企业 SSO') },
  { key: 'entity_id', label: t('IdP entityID'), placeholder: 'http://idp.example.com/adfs/services/trust' },
  { key: 'sso_url', label: t('IdP SSO URL（HTTP-Redirect）'), placeholder: 'https://idp.example.com/adfs/ls/' },
  { key: 'idp_certificate', label: t('IdP 签名证书（PEM 或 base64）'), multiline: true, placeholder: '-----BEGIN CERTIFICATE-----' },
  { key: 'name_id_format', label: t('NameID 格式（选填）'), placeholder: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent' },
  { key: 'attr_name', label: t('姓名属性名（选填）'), placeholder: 'displayName' },
  { key: 'attr_email', label: t('邮箱属性名（选填）'), placeholder: 'email / mail' },
  { key: 'attr_groups', label: t('组属性名（选填，逗号分隔）'), placeholder: 'groups, memberOf' },
  { key: 'clock_skew', label: t('时钟偏移容忍秒数（选填）'), placeholder: '90' },
  { key: 'redirect_base', label: t('对外基地址（选填）'), placeholder: 'https://sso.example.com' },
];

const CRED_FIELDS: Record<string, { key: string; label: string; secret?: boolean; multiline?: boolean; placeholder?: string }[]> = {
  dingtalk: [
    { key: 'client_id', label: t('应用 Client ID（AppKey）'), placeholder: 'dingxxxxxxxxxxxxxx' },
    { key: 'client_secret', label: t('应用 Secret（AppSecret）'), secret: true },
  ],
  wecom: [
    { key: 'corp_id', label: t('企业 ID（CorpID）'), placeholder: 'wwxxxxxxxxxxxxxx' },
    { key: 'agent_id', label: t('应用 AgentId'), placeholder: '1000004' },
    { key: 'secret', label: t('应用 Secret'), secret: true },
    { key: 'contacts_secret', label: t('通讯录同步 Secret（通讯录导入用，选填）'), secret: true, placeholder: t('企业微信后台-管理工具-通讯录同步 的 Secret') },
    { key: 'redirect_base', label: t('回调域名基地址'), placeholder: 'http://ac.example.com' },
  ],
  feishu: [
    { key: 'app_id', label: t('应用 App ID'), placeholder: 'cli_xxxxxxxx' },
    { key: 'app_secret', label: t('应用 App Secret'), secret: true },
    { key: 'redirect_base', label: t('回调域名基地址'), placeholder: 'http://ac.example.com' },
  ],
  saml: SAML_FIELDS,
  'ldap-ad': LDAP_FIELDS,
  openldap: [
    { key: 'label', label: t('登录页显示名'), placeholder: t('如：OpenLDAP 账号') },
    { key: 'server', label: t('服务器地址'), placeholder: 'ldap://127.0.0.1:389' },
    { key: 'bind_dn', label: t('服务账号 DN'), placeholder: 'cn=admin,dc=modsec,dc=local' },
    { key: 'bind_password', label: t('服务账号密码'), secret: true },
    { key: 'base_dn', label: t('用户搜索 Base DN'), placeholder: 'dc=modsec,dc=local' },
    { key: 'user_filter', label: t('用户过滤器'), placeholder: '(uid={username})' },
  ],
};

export default function AuthConfigPage() {
  const { message, modal } = App.useApp();
  const [cfg, setCfg] = useState<AuthConfig | null>(null);
  const [creds, setCreds] = useState<CredsResp | null>(null);
  const [saving, setSaving] = useState(false);
  const [selIdp, setSelIdp] = useState<string>('dingtalk');
  const [mdXml, setMdXml] = useState('');
  const [parsing, setParsing] = useState(false);
  const [form] = Form.useForm();

  const load = () => {
    http.get<never, AuthConfig>('/auth/config').then(setCfg).catch(() => {});
    http.get<never, CredsResp>('/auth/idp-credentials').then(setCreds).catch(() => {});
  };
  useEffect(load, []);

  // 切换凭证渠道时回显已保存配置（secret 显示 ******，留空=不修改）
  useEffect(() => {
    const c = creds?.idps?.[selIdp];
    if (c) form.setFieldsValue({ ...c.fields, enabled: c.enabled });
  }, [selIdp, creds, form]);

  const savePrimary = (v: string) => {
    const opt = IDP_OPTIONS.find((o) => o.value === v);
    modal.confirm({
      title: t('确认切换主认证源？'),
      content: t('主认证源将切换为「{v0}」，所有用户下次认证走新认证源；已在线会话不受影响。确认？', { v0: opt?.label ?? v }),
      onOk: async () => {
        setSaving(true);
        try {
          await http.put('/auth/config', { primary_idp: v, confirm_impact: true });
          message.success(t('已保存并即时生效'));
          load();
        } finally {
          setSaving(false);
        }
      },
    });
  };

  const saveLocal = (patch: Partial<AuthConfig>, impactText?: string) => {
    const doPut = async () => {
      setSaving(true);
      try {
        await http.put('/auth/config', { ...patch, confirm_impact: true });
        message.success(t('已保存并即时生效'));
        load();
      } finally {
        setSaving(false);
      }
    };
    if (impactText) {
      modal.confirm({ title: t('确认变更？'), content: impactText, onOk: doPut });
    } else {
      doPut();
    }
  };

  const saveCreds = async () => {
    const v = await form.validateFields();
    const fields: Record<string, string> = {};
    for (const f of CRED_FIELDS[selIdp]) {
      const val = v[f.key];
      if (val !== undefined && val !== '') fields[f.key] = val;
    }
    if (f2n(selIdp) && fields.agent_id) fields.agent_id = String(parseInt(fields.agent_id, 10));
    setSaving(true);
    try {
      await http.put('/auth/idp-credentials', { idp: selIdp, fields, enabled: !!v.enabled });
      message.success(t('凭证已保存并即时生效（无需重启服务）'));
      load();
    } catch {
      /* 拦截器已提示 */
    } finally {
      setSaving(false);
    }
  };

  function f2n(idp: string): boolean {
    return idp === 'wecom';
  }

  const parseMetadata = async () => {
    if (!mdXml.trim()) {
      message.warning(t('请先粘贴 IdP metadata XML'));
      return;
    }
    setParsing(true);
    try {
      const parsed = await http.post<never, SamlMetaParsed>('/auth/saml/parse-metadata', { xml: mdXml });
      form.setFieldsValue({
        entity_id: parsed.entity_id,
        sso_url: parsed.sso_url,
        idp_certificate: parsed.idp_certificate,
      });
      modal.success({
        title: t('Metadata 解析成功'),
        content: (
          <div style={{ fontSize: 12, wordBreak: 'break-all' }}>
            <div>entityID：{parsed.entity_id}</div>
            <div>SSO URL：{parsed.sso_url}</div>
            <div>{t('证书到期')}：{parsed.cert_not_after || '-'}</div>
          </div>
        ),
      });
    } catch {
      /* 拦截器已提示 */
    } finally {
      setParsing(false);
    }
  };

  const cur = creds?.idps?.[selIdp];
  const fieldDefs = CRED_FIELDS[selIdp] ?? [];

  return (
    <PageContainer
      title={t('认证管理')}
      subTitle={t('单主认证源 + 本地兜底（§18）：登录页默认直达主认证源，本地账号入口显示在登录页下方')}
    >
      <Alert
        type="info"
        showIcon
        message={t('切换认证源的影响')}
        description={t('已在线会话不受影响（auth-token 存活期内）；所有用户下次认证走新认证源。跨认证源不迁移历史身份（切换属重装箱操作）。只有「已启用」的认证源可选为主认证源。')}
        style={{ marginBottom: 16 }}
      />

      <Card title={t('主认证源（单选）')} style={{ marginBottom: 16 }}>
        {cfg ? (
          <Radio.Group value={cfg.primary_idp || undefined} onChange={(e) => savePrimary(e.target.value)}>
            <Space direction="vertical" size={12}>
              {IDP_OPTIONS.map((o) => {
                const configured = cfg.configured?.[o.value];
                return (
                  <Radio key={o.value} value={o.value} disabled={!configured}>
                    <Space>
                      <span>{o.label}</span>
                      <Tag color={configured ? 'green' : 'orange'}>
                        {configured ? t('已启用') : t('未启用（先在下方配置凭证）')}
                      </Tag>
                      {cfg.primary_idp === o.value && <Tag color="blue">{t('当前生效')}</Tag>}
                    </Space>
                  </Radio>
                );
              })}
            </Space>
          </Radio.Group>
        ) : (
          <Typography.Text type="secondary">{t('加载中…')}</Typography.Text>
        )}
        <Typography.Paragraph type="secondary" style={{ marginTop: 16, marginBottom: 0, fontSize: 12 }}>
          登录页行为：主认证源为扫码类或 SAML 时显示品牌跳转页（3 秒自动进入）；为 AD/LDAP 类时直接显示账号密码表单；
          开启本地兜底时，登录页下方同时提供「本地账号登录」入口。
        </Typography.Paragraph>
      </Card>

      <Card title={t('认证源凭证配置')} style={{ marginBottom: 16 }}>
        <Space direction="vertical" size={16} style={{ width: '100%' }}>
          <Space wrap>
            <span>{t('认证源：')}</span>
            <Select
              value={selIdp}
              style={{ width: 200 }}
              onChange={setSelIdp}
              options={IDP_OPTIONS.map((o) => ({
                value: o.value,
                label: `${o.label}${creds?.idps?.[o.value]?.enabled ? t('（已启用）') : ''}`,
              }))}
            />
            {cur?.enabled ? <Tag color="green">{t('已启用')}</Tag> : <Tag color="orange">{t('未启用')}</Tag>}
          </Space>
          {cur?.type === 'oauth' && cur?.callback_url && (
            <Alert
              type="info"
              showIcon
              message={t('回调地址：{v0}', { v0: cur.callback_url })}
              description={t('请在对应 IdP 开放平台的应用后台，把上述地址加入授权回调/重定向 URL 白名单（外网域名场景在下方 redirect_base 字段填写并同步白名单）')}
            />
          )}
          {selIdp === 'saml' && cur?.acs_url && (
            <Alert
              type="info"
              showIcon
              message={t('在客户 IdP 侧登记以下两个地址（本系统自动应答，无需开放额外端口）')}
              description={
                <div style={{ fontSize: 12 }}>
                  <div>
                    ACS：{t('断言消费地址')}{' '}
                    <Typography.Text copyable style={{ wordBreak: 'break-all' }}>{cur.acs_url}</Typography.Text>
                  </div>
                  <div>
                    SP Metadata：{' '}
                    <Typography.Text copyable style={{ wordBreak: 'break-all' }}>{cur.metadata_url}</Typography.Text>
                  </div>
                </div>
              }
            />
          )}
          {selIdp === 'saml' && (
            <div style={{ maxWidth: 560 }}>
              <Typography.Paragraph style={{ marginBottom: 4 }}>{t('解析 IdP Metadata XML（自动填入下表）')}</Typography.Paragraph>
              <Input.TextArea
                value={mdXml}
                onChange={(e) => setMdXml(e.target.value)}
                rows={5}
                placeholder={t('粘贴 IdP metadata XML 全文（AD FS/Okta/Entra 等的 FederationMetadata 下载内容）')}
                style={{ marginBottom: 8 }}
              />
              <Button onClick={parseMetadata} loading={parsing} style={{ marginBottom: 8 }}>
                {t('解析并填入表单')}
              </Button>
            </div>
          )}
          <Form form={form} layout="vertical" style={{ maxWidth: 560 }} onFinish={saveCreds}>
            {fieldDefs.map((f) => (
              <Form.Item key={f.key} label={f.label} name={f.key} extra={f.secret ? SECRET_HINT : undefined}>
                {f.secret ? (
                  <Input.Password placeholder={t('••••••（已配置则显示 ******）')} autoComplete="new-password" />
                ) : f.multiline ? (
                  <Input.TextArea rows={4} placeholder={f.placeholder} style={{ fontFamily: 'monospace' }} />
                ) : (
                  <Input placeholder={f.placeholder} />
                )}
              </Form.Item>
            ))}
            <Form.Item label={t('启用该认证源')} name="enabled" valuePropName="checked">
              <Switch />
            </Form.Item>
            <Button type="primary" htmlType="submit" loading={saving}>
              保存凭证（即时生效）
            </Button>
          </Form>
        </Space>
      </Card>

      <Card title={t('客户端连接验证策略')} style={{ marginBottom: 16 }}>
        <Space direction="vertical" size={16} style={{ width: '100%' }}>
          <div>
            <Space>
              <Switch
                checked={(cfg?.client_verify_policy ?? 'off') === 'strict'}
                onChange={(v) =>
                  saveLocal(
                    { client_verify_policy: v ? 'strict' : 'off' },
                    v
                      ? t('开启后：客户端发起的 VPN 连接每次都需网页验证（浏览器 8 小时免扫码不再适用于客户端）；仅门户「一键连接」通过一次性票据免验证。官方 OpenVPN/Tunnelblick 等第三方客户端将始终要求网页验证。确认开启？')
                      : t('关闭后恢复现状：浏览器认证过一次后 8 小时内客户端连接免扫码。确认？'),
                  )
                }
              />
              <span>{t('严格模式：客户端连接一律网页验证')}</span>
              <Tag color={cfg?.client_verify_policy === 'strict' ? 'red' : 'blue'}>
                {cfg?.client_verify_policy === 'strict' ? t('已开启') : t('默认关闭')}
              </Tag>
            </Space>
            <Typography.Paragraph type="secondary" style={{ marginBottom: 0, fontSize: 12, marginTop: 4 }}>
              {t('开启前提：员工客户端（Android App / Windows 客户端）须为支持一键连接票据的版本，否则门户一键连接也会要求网页验证。网页一键连接不受影响（凭一次性票据静默通过）。')}
            </Typography.Paragraph>
          </div>
        </Space>
      </Card>

      <Card title={t('本地账号兜底')} style={{ marginBottom: 16 }}>
        <Space direction="vertical" size={16} style={{ width: '100%' }}>
          <div>
            <Space>
              <Switch
                checked={cfg?.local_auth_enabled ?? true}
                onChange={(v) =>
                  saveLocal(
                    { local_auth_enabled: v },
                    v ? t('启用本地账号兜底。') : t('禁用后本地账号将无法登录（含应急通道），确定？'),
                  )
                }
              />
              <span>{t('启用本地账号登录（临时/应急用途）')}</span>
              <Tag color="blue">{t('默认开启')}</Tag>
            </Space>
            <Typography.Paragraph type="secondary" style={{ marginBottom: 0, fontSize: 12, marginTop: 4 }}>
              本地账号 = 管理台「用户管理」中创建的本地用户（如 opuser1）。用途：管理员 break-glass、企业认证源故障应急、未接入认证源前的试用。
            </Typography.Paragraph>
          </div>
          <div>
            <Space>
              <Switch checked={cfg?.hide_local_link ?? false} onChange={(v) => saveLocal({ hide_local_link: v })} />
              <span>{t('登录页隐藏「本地账号登录」入口')}</span>
            </Space>
            <Typography.Paragraph type="secondary" style={{ marginBottom: 0, fontSize: 12, marginTop: 4 }}>
              仅隐藏入口；管理台本地登录不受影响。
            </Typography.Paragraph>
          </div>
        </Space>
      </Card>

      <Card>
        <Button onClick={load}>{t('刷新')}</Button>
      </Card>
    </PageContainer>
  );
}
