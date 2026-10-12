# 发布检查清单

> Modsafe CE 每次对外发布前逐项确认。仓库不携带任何环境的密钥与凭据，部署侧密钥由部署方自行生成。

## 安全

- [ ] 对发布树全量执行密钥/口令扫描，零命中方可推送公开 remote（复核 `data/`、`*.db`、构建产物均已排除且不入库）
- [ ] 部署侧密钥（CA 链、OpenVPN server.key / ta.key、license 密钥对、管理台口令）全部由部署方自行生成，任何密钥材料不得进入仓库或发布物
- [ ] [SECURITY.md](SECURITY.md) 安全联络方式有效

## 发布工程

- [x] 环境值外部化（2026-10-11）：部署拓扑全部 env 注入，代码零内置地址；必填缺失 fail-fast 拒绝启动（`MODSAFE_PORTAL_BASE` 三模块统一命名）
- [ ] CE 构建（无 EE tag）与 EE 构建产物 diff 审查——EE 专属签发器与功能模块不在本仓
- [ ] `THIRD-PARTY-NOTICES` 生成并随发布物分发
- [ ] 部署模板落进 `deploy/`（systemd unit、nginx TLS 反代样例、一键安装演练通过）
- [ ] 三条 HTTP 契约文档冻结进 `docs/api/`（web→control、adapter→control internal、control↔nodeagent）
- [ ] `make vet` 与 `make test` 全绿
