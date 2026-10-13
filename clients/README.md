# clients

客户端源码目录。两端均为上游开源项目的品牌 fork，**源码随本仓分发即满足其 GPL 合规要求**；本目录不含任何成品二进制与签名密钥。

| 目录 | 客户端 | 上游 | 许可 |
|---|---|---|---|
| `android/` | Modsafe 安卓客户端 | [ics-openvpn](https://github.com/schwabe/ics-openvpn) v0.7.65 | GPL（见 `android/doc/LICENSE.txt`；remoteExample 等组件 Apache-2.0） |
| `windows/` | modsafe-gui（Windows 桌面客户端） | [openvpn-gui](https://github.com/OpenVPN/openvpn-gui) | GPLv2（见 `windows/COPYING`） |

## 门户域名：首启配置，不写死

两端客户端的门户域名均在**首次启动时由用户配置**，代码中不硬编码任何部署地址：

- **Android**：`MainActivity` 启动时检查 `PortalConfig.isConfigured()`，未配置则弹出全屏 `PortalSetupDialog`（不可取消），输入 `https://门户地址` 后存入 SharedPreferences。扫码导入 / WebAuth / 升级检查的域名白名单均动态读取该配置（`PortalConfig.allowedHosts()`），未配置时全拒绝（安全默认）。NSC 不 pin 特定域名，信任系统 CA + 捆绑的产品根 CA（`opensec.crt`）。
- **Windows**：`WinMain` 启动时检查注册表 `HKCU\Software\Modsafe\portal_url`，未配置则弹输入对话框，保存后生效。

## modsafe 侧改动概述

- **android**：扫码导入（QrImportActivity，扫门户二维码一次性导入 .ovpn）、内嵌 WebAuth 认证（ModsafeAuthActivity，与门户 SSO 同源）、去除 Access Server 导入入口、精简主界面、全量品牌化（应用名/图标/TV banner）；`main/src/main/res/raw/opensec.crt` 为产品根 CA 锚点（自签，CN=Modsafe）。
- **windows**：modsafe-gui 品牌化（注册表键、托盘、连接命令），与 `launcher/`（一键连接桥）配合使用。

## 构建

- **android**：Android Studio / Gradle，需 Android SDK + NDK（内含 OpenVPN3 C++ 构建）。签名配置从构建机 `~/.gradle/gradle.properties` 读取（`keystoreFile` / `keystorePassword` / `keystoreAliasPassword` 属性），密钥文件不进仓库。
- **windows**：CMake + MinGW 或 MSVC，见目录内 `BUILD.rst`。

构建产物（`build/`、`.cxx/`、`.gradle/`、`local.properties`、`*.keystore`、`*.jks`）已在根 `.gitignore` 排除，绝不入库。
