@echo off
rem modsafe VPN one-click helper: modsafe:// protocol + resident status listener (#115)
rem The listener (127.0.0.1:11443/status) lets the portal query local connection state instantly.
setlocal
set DST=%LOCALAPPDATA%\modsafeLauncher
if not exist "%DST%" mkdir "%DST%"
copy /y "%~dp0modsafe-launcher.exe" "%DST%\modsafe-launcher.exe" >nul
rem #91：清理改名前的旧文件 modsec-launcher.exe（存在则删；目标是旧名，勿写成新名——新名是上一行刚复制的安装产物）
del "%DST%\modsec-launcher.exe" >nul 2>&1

rem #94：删除已废弃的 modsafevpn:// 旧注册（不再支持）——置于注册之前执行，
rem 免得 reg delete 的 errorlevel（旧键不存在=1）污染文末的安装成败判定
reg delete "HKCU\Software\Classes\modsafevpn" /f >nul 2>&1

reg add "HKCU\Software\Classes\modsafe" /ve /d "URL:模方安全" /f >nul
reg add "HKCU\Software\Classes\modsafe" /v "URL Protocol" /f >nul
reg add "HKCU\Software\Classes\modsafe\DefaultIcon" /ve /d "%DST%\modsafe-launcher.exe" /f >nul
reg add "HKCU\Software\Classes\modsafe\shell\open\command" /ve /d "\"%DST%\modsafe-launcher.exe\" \"%%1\"" /f >nul

rem #115：状态监听常驻（登录自启 + 立即拉起），供门户实时查询本机连接状态
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v ModsafeLauncher /t REG_SZ /d "\"%DST%\modsafe-launcher.exe\" --listen" /f >nul
start "" "%DST%\modsafe-launcher.exe" --listen

if %errorlevel%==0 (
  echo 安装完成！现在可以在自助门户使用「一键连接」。
  echo 如需卸载：reg delete HKCU\Software\Classes\modsafe /f 和 reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v ModsafeLauncher /f
) else (
  echo 注册失败，请重试或联系管理员。
)
pause
