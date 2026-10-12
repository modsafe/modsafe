# Modsafe CE（社区版）

Modsafe 是一套**零信任接入服务端**：把企业身份源（OIDC / SAML / LDAP / 钉钉 / 企业微信 / 飞书）接入统一认证门户，并为接入网关提供用户管控、证书生命周期、资源授权与会话审计。

数据面内核采用 OpenVPN 社区版（GPLv2）。本仓库包含服务端管控面与客户端**源码**（`clients/`，GPL 系许可——源码随仓分发即满足其合规要求）；不含内核与服务端成品二进制，不含任何密钥材料（客户端签名密钥经构建机 `~/.gradle/gradle.properties` 注入）。

> 状态：首个开源版本（v0.1.0），API 与部署形态仍在演进；发布流程见 [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md)。

## 组件

| 目录 | 模块 | 说明 |
|---|---|---|
| `adapter/` | 认证适配器（:8000） | OIDC / SAML / LDAP / 钉钉 / 企微 / 飞书协议对话，向上暴露标准 OIDC 门面 |
| `control/` | 控制面（:9443） | 管理 API、用户/组/证书/授权/审计，内嵌管理台与员工门户（go:embed 同源分发） |
| `nodeagent/` | 节点代理（:7503 / :7505） | 网关主机侧代理：内核管理、会话采集、watchdog |
| `launcher/` | Windows 一键连接桥（:11443） | `modsafe://` 深链 → 门户一次性下发配置 → 本机连接状态回查 |
| `web/` | 前端源码 | 管理台 SPA + 零依赖门户单页（React 18 + antd 5，vite 双入口） |
| `clients/android/` | 安卓客户端 | OpenVPN for Android（ics-openvpn v0.7.65）品牌 fork（GPL）：扫码导入、内嵌 WebAuth 认证、品牌化 UI |
| `clients/windows/` | Windows 桌面客户端 | OpenVPN GUI 品牌 fork（GPLv2）：modsafe-gui 品牌化、托盘连接 |

## 架构约束

- 模块间**零 Go import**，只经 HTTP 契约 + 共享令牌通信；依赖方向单向：

  ```
  web（浏览器） ──/api/v1──▶ control ◀──internal API── adapter ──▶ 企业 IdP
                              │
                              ▼
                           nodeagent ──▶ OpenVPN management / IPVS / 文件系统
  ```

- `control/web/dist` 是 go:embed 目标目录，仅含 `.gitkeep` 占位；构建期由 `scripts/copy-web` 从 `web/` 构建产物同步，不入 git。
- 商业版（EE）功能以 license 功能位门控：校验器随本仓开源（`control/license.go`），签发器不随本仓分发。版本差异见下节[版本对比](#版本对比)。

## 版本对比

| 能力 | CE 社区版（本仓） | EE 商业版 |
|---|---|---|
| 许可 | [Apache-2.0](LICENSE)，免费使用 | 商业授权（Ed25519 离线 license） |
| 统一认证门户（对上暴露标准 OIDC） | ✅ | ✅ |
| 钉钉扫码登录 | ✅ | ✅ |
| LDAP / AD 域账号 | ✅ | ✅ |
| 本地账号 + TOTP 双因素 | ✅ | ✅ |
| 飞书 / 企业微信扫码 | 代码内置、默认未启用（需自行注册应用并配置凭据） | ✅（厂商协助交付） |
| SAML 企业 SSO | 代码内置；启用受 license `saml` 功能位门控 | ✅（按授权启用） |
| 用户 / 组 / 设备 / 证书生命周期 / 资源授权 / 审计与告警 | ✅ | ✅ |
| 国密套件（SM4-GCM / SM3） | ✅（需 GM 构建的服务端二进制） | ✅（GM 构建随交付） |
| 多节点 / HA watchdog / 会话采集 | ✅（env 配置启用） | ✅ |
| License 配额管控（用户数 / 并发 / 节点数）与有效期 | —（无 license，试用模式不限量） | ✅ |
| License 校验器 | ✅ 随本仓开源 | ✅ |
| License 签发器 | —（不随本仓分发） | ✅ |
| 支持 | 社区自助 | 商业 SLA |

> **试用模式说明（两版同代码）**：无 license 时自首次启动起 30 天全功能试用，到期后 15 天宽限（功能全可用、红横幅提醒）；宽限期满拒绝新增用户与新认证，已在线会话不强制踢出。CE 不内置验证公钥（避免公钥公开 + 厂商密钥泄漏 = 授权可伪造的组合），导入正式授权需经 `MODSAFE_LICENSE_PUB` env 或 `data/license.pub` 注入公钥，未注入时始终处于试用模式。

## 构建

依赖：Go ≥ 1.27、Node.js ≥ 20。客户端构建另需：Android SDK/NDK（`clients/android/`）、MinGW 或 MSVC（`clients/windows/`），上游构建文档随各自目录分发。

```bash
make web-build   # 前端构建 → web/dist
make build       # 同步 embed 并编译四模块
make test        # 全模块测试
```

## 环境变量

**配置单一来源**：部署拓扑（门户/认证/网关地址）全部经环境变量注入，代码零内置地址——必填项缺失时进程拒绝启动（fail-fast），可选功能（HA watchdog、双节点下发）未配置时自动停用。

同一语义全仓同名：`MODSAFE_PORTAL_BASE`（门户基址，adapter/control/launcher 三模块共用）、`MODSAFE_VPN_REMOTE`（.ovpn 接入地址种子，DB 设置可覆盖）、`NODE_AGENT_193`（node-2 代理基址）。变量清单见 [examples/](examples/) 各模块 `.env.example`。

## 许可

- 服务端管控面以 [Apache-2.0](LICENSE) 发布；`clients/` 下客户端为其上游 GPL 许可的 fork（Android：GPL，remoteExample 等组件 Apache v2；Windows GUI：GPLv2），许可文件随各自目录分发（`clients/android/doc/LICENSE.txt`、`clients/windows/COPYING`）。第三方组件说明见 [NOTICE](NOTICE)。
- "OpenVPN" 是 OpenVPN Inc 的商标，本仓库仅作指明性使用。
