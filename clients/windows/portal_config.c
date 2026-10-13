/*
 * Modsafe 门户域名配置（Windows 客户端）：首次启动时由用户配置，不写死。
 * 存储于 HKCU\Software\Modsafe\portal_url；未配置时弹输入对话框。
 */
#include <windows.h>
#include <tchar.h>

#define IDD_PORTAL_SETUP 1001
#define IDC_PORTAL_URL  1002
#define IDC_PORTAL_HINT 1003

static TCHAR g_portal_url[256] = _T("");

/* ---- 注册表读写 ---- */

BOOL GetPortalUrl(LPTSTR buf, DWORD bufLen)
{
    HKEY hKey;
    DWORD type, len = bufLen * sizeof(TCHAR);
    if (RegOpenKeyEx(HKEY_CURRENT_USER, _T("SOFTWARE\\Modsafe"), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return FALSE;
    BOOL ok = RegQueryValueEx(hKey, _T("portal_url"), NULL, &type, (LPBYTE)buf, &len) == ERROR_SUCCESS
              && type == REG_SZ && len >= sizeof(TCHAR);
    RegCloseKey(hKey);
    return ok;
}

BOOL SetPortalUrl(LPCTSTR url)
{
    HKEY hKey;
    if (RegCreateKeyEx(HKEY_CURRENT_USER, _T("SOFTWARE\\Modsafe"), 0, NULL,
                       REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return FALSE;
    BOOL ok = RegSetValueEx(hKey, _T("portal_url"), 0, REG_SZ,
                            (const BYTE *)url, (DWORD)((_tcslen(url) + 1) * sizeof(TCHAR))) == ERROR_SUCCESS;
    RegCloseKey(hKey);
    return ok;
}

/* ---- 首启输入对话框（内存模板，避免 .rc 资源改动） ---- */

static INT_PTR CALLBACK PortalSetupProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    (void)lParam;
    switch (msg) {
    case WM_INITDIALOG:
        SetWindowText(hDlg, _T("Modsafe portal setup"));
        SetWindowText(GetDlgItem(hDlg, IDC_PORTAL_HINT),
                      _T("Enter your organization's Modsafe portal address:"));
        SetFocus(GetDlgItem(hDlg, IDC_PORTAL_URL));
        return FALSE;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            GetWindowText(GetDlgItem(hDlg, IDC_PORTAL_URL), g_portal_url, _countof(g_portal_url));
            if (_tcslen(g_portal_url) > 0) {
                EndDialog(hDlg, IDOK);
            } else {
                MessageBox(hDlg, _T("Please enter a valid https:// URL."), _T("Invalid"), MB_OK | MB_ICONWARNING);
            }
        } else if (LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, IDCANCEL);
        }
        return TRUE;
    }
    return FALSE;
}

/* 显示首启配置对话框；返回 TRUE=已配置 */
static BOOL PromptPortalSetup(void)
{
    /* 内存对话框模板：标签 + 编辑框 + OK/Cancel */
    #pragma pack(push, 1)
    typedef struct {
        DLGTEMPLATE dt;
        WORD wMenu, wClass, wTitle;
        WORD wPointSize;
        WCHAR szTitle[20];
        struct {
            DLGITEMTEMPLATE dit;
            WORD wClass, wTitle;
            WORD wId;
            WORD wStyle, x, y, cx, cy;
        } label, edit, btnOk, btnCancel;
    } PortalDlg;
    #pragma pack(pop)

    ZeroMemory(&PortalDlg, sizeof(PortalDlg));
    PortalDlg.dt.style = DS_MODALFRAME | DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU;
    PortalDlg.dt.cdit = 4;
    PortalDlg.wPointSize = 8;
    lstrcpyW(PortalDlg.szTitle, L"Modsafe");

    /* 标签 */
    PortalDlg.label.dit.style = WS_CHILD | WS_VISIBLE | SS_LEFT;
    PortalDlg.label.dit.x = 10; PortalDlg.label.dit.y = 10;
    PortalDlg.label.dit.cx = 280; PortalDlg.label.dit.cy = 20;
    PortalDlg.label.wClass = 0xFFFF; PortalDlg.label.wTitle = 0xFFFF; /* static */
    PortalDlg.label.wId = IDC_PORTAL_HINT;

    /* 编辑框 */
    PortalDlg.edit.dit.style = WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL;
    PortalDlg.edit.dit.x = 10; PortalDlg.edit.dit.y = 35;
    PortalDlg.edit.dit.cx = 280; PortalDlg.edit.dit.cy = 14;
    PortalDlg.edit.wClass = 0xFFFF; PortalDlg.edit.wTitle = 0xFFFF; /* edit */
    PortalDlg.edit.wId = IDC_PORTAL_URL;

    /* OK */
    PortalDlg.btnOk.dit.style = WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON;
    PortalDlg.btnOk.dit.x = 130; PortalDlg.btnOk.dit.y = 60;
    PortalDlg.btnOk.dit.cx = 50; PortalDlg.btnOk.dit.cy = 14;
    PortalDlg.btnOk.wClass = 0xFFFF; PortalDlg.btnOk.wTitle = 0xFFFF; /* button */
    PortalDlg.btnOk.wId = IDOK;

    /* Cancel */
    PortalDlg.btnCancel.dit.style = WS_CHILD | WS_VISIBLE;
    PortalDlg.btnCancel.dit.x = 190; PortalDlg.btnCancel.dit.y = 60;
    PortalDlg.btnCancel.dit.cx = 50; PortalDlg.btnCancel.dit.cy = 14;
    PortalDlg.btnCancel.wClass = 0xFFFF; PortalDlg.btnCancel.wTitle = 0xFFFF; /* button */
    PortalDlg.btnCancel.wId = IDCANCEL;

    INT_PTR r = DialogBoxIndirectParam(GetModuleHandle(NULL),
                                       (LPCDLGTEMPLATE)&PortalDlg,
                                       NULL, PortalSetupProc, 0);
    if (r == IDOK && _tcslen(g_portal_url) > 0) {
        return SetPortalUrl(g_portal_url);
    }
    return FALSE;
}

/* 供 WinMain 调用：未配置则弹框；返回 TRUE=已配置（或用户取消后重试） */
BOOL EnsurePortalConfigured(void)
{
    TCHAR url[256];
    if (GetPortalUrl(url, _countof(url)) && _tcslen(url) > 0)
        return TRUE;
    return PromptPortalSetup();
}
