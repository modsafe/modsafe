/*
 * Modsafe 门户域名配置（Windows 客户端）：首次启动时由用户配置，不写死。
 * 存储于 HKCU\Software\Modsafe\portal_url；未配置时弹输入对话框。
 */
#include <windows.h>
#include <tchar.h>

#define IDD_PORTAL_SETUP 1001
#define IDC_PORTAL_URL  1002

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

/* ---- 首启输入对话框（内存模板；packed 布局与 Win32 解析器一致） ---- */

static INT_PTR CALLBACK PortalSetupProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    (void)lParam;
    switch (msg) {
    case WM_INITDIALOG:
        /* 标题/标签/按钮文案均在模板内；首个可聚焦控件=编辑框 */
        return TRUE;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            /* 枚举子控件找编辑框（GetWindow/GetDlgCtrlID 为确定存在的导出） */
            HWND hChild = GetWindow(hDlg, GW_CHILD);
            while (hChild != NULL) {
                if (GetDlgCtrlID(hChild) == IDC_PORTAL_URL) {
                    GetWindowText(hChild, g_portal_url, _countof(g_portal_url));
                    break;
                }
                hChild = GetWindow(hChild, GW_HWNDNEXT);
            }
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

static BOOL PromptPortalSetup(void)
{
    /* DLGTEMPLATE(18) + menu(2) + class(2) + 标题串；
       每项：DLGITEMTEMPLATE(20) + 类原子(2+2) + 标题串 + 附加数据计数(2) */
    #pragma pack(push, 1)
    typedef struct {
        DLGTEMPLATE dt;
        WORD wMenu, wClass;
        WCHAR szTitle[16];
        struct {
            DLGITEMTEMPLATE dit;
            WORD wClassAtom;          /* 0xFFFF = 预定义类 */
            WORD wClassCode;          /* 0x0082 静态 / 0x0081 编辑 / 0x0080 按钮 */
            WCHAR szItemTitle[64];
            WORD wExtra;              /* 附加创建数据字节数 = 0 */
        } label, edit, btnOk, btnCancel;
    } PortalTemplate;
    #pragma pack(pop)

    PortalTemplate t;
    ZeroMemory(&t, sizeof(t));
    t.dt.style = DS_MODALFRAME | DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_SETFONT;
    t.dt.cdit = 4;
    t.dt.cx = 300;
    t.dt.cy = 92;
    t.wMenu = 0;
    t.wClass = 0;
    lstrcpyW(t.szTitle, L"Modsafe");

    /* 标签（静态） */
    t.label.dit.style = WS_CHILD | WS_VISIBLE | SS_LEFT;
    t.label.dit.x = 10; t.label.dit.y = 10;
    t.label.dit.cx = 280; t.label.dit.cy = 16;
    t.label.dit.id = (WORD)-1;
    t.label.wClassAtom = 0xFFFF; t.label.wClassCode = 0x0082;
    lstrcpyW(t.label.szItemTitle, L"Enter your organization's portal address (https://...):");

    /* 编辑框 */
    t.edit.dit.style = WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL;
    t.edit.dit.x = 10; t.edit.dit.y = 32;
    t.edit.dit.cx = 280; t.edit.dit.cy = 16;
    t.edit.dit.id = IDC_PORTAL_URL;
    t.edit.wClassAtom = 0xFFFF; t.edit.wClassCode = 0x0081;

    /* OK */
    t.btnOk.dit.style = WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON;
    t.btnOk.dit.x = 100; t.btnOk.dit.y = 58;
    t.btnOk.dit.cx = 60; t.btnOk.dit.cy = 18;
    t.btnOk.dit.id = IDOK;
    t.btnOk.wClassAtom = 0xFFFF; t.btnOk.wClassCode = 0x0080;
    lstrcpyW(t.btnOk.szItemTitle, L"OK");

    /* Cancel */
    t.btnCancel.dit.style = WS_CHILD | WS_VISIBLE;
    t.btnCancel.dit.x = 170; t.btnCancel.dit.y = 58;
    t.btnCancel.dit.cx = 60; t.btnCancel.dit.cy = 18;
    t.btnCancel.dit.id = IDCANCEL;
    t.btnCancel.wClassAtom = 0xFFFF; t.btnCancel.wClassCode = 0x0080;
    lstrcpyW(t.btnCancel.szItemTitle, L"Cancel");

    INT_PTR r = DialogBoxIndirectParam(GetModuleHandle(NULL),
                                       (LPCDLGTEMPLATE)&t,
                                       NULL, PortalSetupProc, 0);
    if (r == IDOK && _tcslen(g_portal_url) > 0) {
        return SetPortalUrl(g_portal_url);
    }
    return FALSE;
}

/* 供 WinMain 调用：未配置则弹框；返回 TRUE=已配置 */
BOOL EnsurePortalConfigured(void)
{
    TCHAR url[256];
    if (GetPortalUrl(url, _countof(url)) && _tcslen(url) > 0)
        return TRUE;
    return PromptPortalSetup();
}
