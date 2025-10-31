#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <shlwapi.h>
#include "../_include/beacon.h"

#pragma comment(lib, "Shlwapi.lib")

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileAttributesW(LPCWSTR lpFileName);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindClose(HANDLE hFindFile);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileAttributesA(LPCSTR lpFileName);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FileTimeToSystemTime(const FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT BOOL WINAPI SHLWAPI$PathFileExistsA(LPCSTR pszPath);
DECLSPEC_IMPORT int WINAPI MSVCRT$sprintf(char *str, const char *format, ...);
DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char *str, size_t size, const char *format, ...);
DECLSPEC_IMPORT void* WINAPI MSVCRT$malloc(size_t size);
DECLSPEC_IMPORT void WINAPI MSVCRT$free(void *ptr);
DECLSPEC_IMPORT int WINAPI MSVCRT$strcmp(const char *s1, const char *s2);
DECLSPEC_IMPORT int WINAPI MSVCRT$strncmp(const char *s1, const char *s2, size_t n);
DECLSPEC_IMPORT char* WINAPI MSVCRT$strstr(const char *haystack, const char *needle);
DECLSPEC_IMPORT char* WINAPI MSVCRT$strrchr(const char *s, int c);
DECLSPEC_IMPORT char* WINAPI MSVCRT$strtok(char *str, const char *delim);
DECLSPEC_IMPORT size_t WINAPI MSVCRT$strlen(const char *s);
DECLSPEC_IMPORT int WINAPI MSVCRT$tolower(int c);
DECLSPEC_IMPORT int __cdecl MSVCRT$_stricmp(const char *s1, const char *s2);
DECLSPEC_IMPORT void* WINAPI MSVCRT$memcpy(void *dest, const void *src, size_t n);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);

// NT native API (stealthier file IO)
typedef long NTSTATUS;
typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        void*    Pointer;
    } DUMMYUNIONNAME;
    unsigned long long Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,
    FileBothDirectoryInformation,
    FileBasicInformation,
    FileStandardInformation = 5,
} FILE_INFORMATION_CLASS;

typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    unsigned long NumberOfLinks;
    unsigned char DeletePending;
    unsigned char Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtReadFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

#ifndef S_OK
#define S_OK 0x00000000
#endif

#ifndef STGM_READ
#define STGM_READ 0x00000000L
#endif
#ifndef STGM_SHARE_DENY_WRITE
#define STGM_SHARE_DENY_WRITE 0x00000020L
#endif

#define OOXML_SCAN_WINDOW (256 * 1024) // 256KB head/tail scan

// Dynamic OLE32 function pointers
typedef HRESULT (WINAPI *PFN_StgIsStorageFile)(LPCWSTR);
typedef HRESULT (WINAPI *PFN_StgOpenStorage)(LPCWSTR, void*, DWORD, void*, DWORD, void**);

static PFN_StgIsStorageFile pStgIsStorageFile = NULL;
static PFN_StgOpenStorage   pStgOpenStorage   = NULL;

static void ensure_ole32_resolved() {
    if (pStgIsStorageFile && pStgOpenStorage) return;
    HMODULE hOle = KERNEL32$GetModuleHandleA("ole32.dll");
    if (!hOle) return; // do not load explicitly to avoid new DLL loads
    pStgIsStorageFile = (PFN_StgIsStorageFile) KERNEL32$GetProcAddress(hOle, "StgIsStorageFile");
    pStgOpenStorage   = (PFN_StgOpenStorage)   KERNEL32$GetProcAddress(hOle, "StgOpenStorage");
}

// Binary-safe search for pattern in buffer
static BOOL buffer_contains(const char* buf, DWORD len, const char* pat) {
    if (!buf || !pat) return FALSE;
    size_t plen = MSVCRT$strlen(pat);
    if (plen == 0 || len < (DWORD)plen) return FALSE;
    for (DWORD i = 0; i + plen <= len; i++) {
        if (buf[i] == pat[0]) {
            DWORD j = 1;
            for (; j < plen; j++) {
                if ((unsigned char)buf[i + j] != (unsigned char)pat[j]) break;
            }
            if (j == plen) return TRUE;
        }
    }
    return FALSE;
}

// Strict VBA macro check (OOXML-only here). OLE path is disabled for stability
BOOL CheckForVBAMacrosStrict(const char* filepath, BOOL use_ole) {
    (void)use_ole; // OLE disabled by default; only OOXML detection is used
    if (!filepath) return FALSE;

    HANDLE h = KERNEL32$CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;

    FILE_STANDARD_INFORMATION finfo = {0};
    IO_STATUS_BLOCK ios = {0};
    NTSTATUS st = NTDLL$NtQueryInformationFile(h, &ios, &finfo, sizeof(finfo), FileStandardInformation);
    if (st != 0 || finfo.EndOfFile.QuadPart == 0) { KERNEL32$CloseHandle(h); return FALSE; }

    ULONGLONG total = (ULONGLONG)finfo.EndOfFile.QuadPart;
    DWORD win = (DWORD)((total > OOXML_SCAN_WINDOW) ? OOXML_SCAN_WINDOW : total);

    char* buf = (char*)MSVCRT$malloc(win);
    if (!buf) { KERNEL32$CloseHandle(h); return FALSE; }

    // Read head via NtReadFile at offset 0
    LARGE_INTEGER off; off.QuadPart = 0;
    ios.Status = 0; ios.Information = 0;
    st = NTDLL$NtReadFile(h, NULL, NULL, NULL, &ios, buf, win, &off, NULL);
    if (st != 0 || ios.Information < 4) { MSVCRT$free(buf); KERNEL32$CloseHandle(h); return FALSE; }

    BOOL isZip = (buf[0] == 'P' && buf[1] == 'K');
    BOOL anyHit = buffer_contains(buf, (DWORD)ios.Information, "vbaProject.bin");

    if (!anyHit && total > win) {
        // Read tail via offset
        off.QuadPart = (LONGLONG)(total - win);
        ios.Status = 0; ios.Information = 0;
        st = NTDLL$NtReadFile(h, NULL, NULL, NULL, &ios, buf, win, &off, NULL);
        if (st == 0 && ios.Information >= 4) {
            if (!isZip) isZip = (buf[0] == 'P' && buf[1] == 'K');
            anyHit = buffer_contains(buf, (DWORD)ios.Information, "vbaProject.bin");
        }
    }

    MSVCRT$free(buf);
    KERNEL32$CloseHandle(h);
    return (isZip && anyHit);
}

typedef struct {
    char** directories;
    int dir_count;
    char** filetypes;
    int filetype_count;
    char** keywords;
    int keyword_count;
    BOOL search_contents;
    BOOL system_dirs;
    ULONGLONG max_file_size_kb;
    SYSTEMTIME before_date;
    SYSTEMTIME after_date;
    BOOL check_for_macro;  // -v: OOXML macro detection
    BOOL has_date_filter;
    int result_count;
} SearchOptions;

#define MAX_RESULTS 1000
#define MAX_PATH_LENGTH 260
#define MAX_CONTENT_BUFFER_SIZE (10 * 1024 * 1024)
#define CONTEXT_BUFFER_SIZE 50

// Forward declarations for helpers
BOOL MatchesFiletype(const char* filepath, SearchOptions* opts);
BOOL MatchesKeyword(const char* filename, SearchOptions* opts);
BOOL MatchesDateFilter(const FILETIME* filetime, SearchOptions* opts);
BOOL SearchFileContents(const char* filepath, SearchOptions* opts);
BOOL IsFolderValid(const char* path, SearchOptions* opts);
void NormalizePath(char* path);

// Simple wildcard matching function (supports * and ?)
BOOL MatchWildcard(const char* pattern, const char* str) {
    const char* s = str;
    const char* p = pattern;
    const char* star = NULL;
    const char* ss = NULL;
    while (*s) {
        if (*p == '?' || MSVCRT$tolower(*p) == MSVCRT$tolower(*s)) { s++; p++; continue; }
        if (*p == '*') { star = p++; ss = s; continue; }
        if (star) { p = star + 1; s = ++ss; continue; }
        return FALSE;
    }
    while (*p == '*') p++;
    return !*p;
}

BOOL MatchesKeyword(const char* filename, SearchOptions* opts) {
    if (opts->keyword_count == 0) return TRUE;
    for (int i = 0; i < opts->keyword_count; i++) {
        const char* kw = opts->keywords[i];
        if (!kw) continue;
        if (MatchWildcard(kw, filename)) return TRUE;
        // fallback: case-insensitive substring
        size_t flen = MSVCRT$strlen(filename);
        size_t klen = MSVCRT$strlen(kw);
        char* lf = (char*)MSVCRT$malloc(flen + 1);
        char* lk = (char*)MSVCRT$malloc(klen + 1);
        if (lf && lk) {
            for (size_t j = 0; j < flen; j++) lf[j] = (char)MSVCRT$tolower((unsigned char)filename[j]);
            lf[flen] = '\0';
            for (size_t j = 0; j < klen; j++) lk[j] = (char)MSVCRT$tolower((unsigned char)kw[j]);
            lk[klen] = '\0';
            BOOL hit = (MSVCRT$strstr(lf, lk) != NULL);
            MSVCRT$free(lf); MSVCRT$free(lk);
            if (hit) return TRUE;
        } else { if (lf) MSVCRT$free(lf); if (lk) MSVCRT$free(lk); }
    }
    return FALSE;
}

BOOL MatchesFiletype(const char* filepath, SearchOptions* opts) {
    const char* ext = MSVCRT$strrchr(filepath, '.');
    if (!ext) return FALSE;
    for (int i = 0; i < opts->filetype_count; i++) {
        if (opts->filetypes[i] && MSVCRT$_stricmp(ext, opts->filetypes[i]) == 0) return TRUE;
    }
    return FALSE;
}

// Check if directory should be excluded
BOOL IsFolderValid(const char* path, SearchOptions* opts) {
    // If system_dirs flag is enabled, allow all directories
    if (opts->system_dirs) {
        return TRUE;
    }
    
    // Normalize path by creating a copy and replacing double backslashes
    size_t len = MSVCRT$strlen(path);
    char* normalized_path = (char*)MSVCRT$malloc(len + 1);
    if (!normalized_path) return TRUE; // If malloc fails, allow the path
    
    MSVCRT$memcpy(normalized_path, path, len + 1);
    NormalizePath(normalized_path);
    
    // Exclude root-level system directories only (not subdirectories of user-specified paths)
    // Check for exact root-level matches: C:\Windows, C:\Program Files, etc.
    if (MSVCRT$strstr(normalized_path, ":\\Windows") && 
        (MSVCRT$strlen(normalized_path) <= 10 || normalized_path[10] == '\\' || normalized_path[10] == '\0')) {
        MSVCRT$free(normalized_path);
        return FALSE;
    }
    
    if (MSVCRT$strstr(normalized_path, ":\\Program Files")) {
        // Check if it's root-level Program Files (not Program Files (x86) or subdirectories)
        const char* pf_pos = MSVCRT$strstr(normalized_path, ":\\Program Files");
        if (pf_pos && (MSVCRT$strlen(pf_pos) == 15 || (pf_pos[15] == '\\' || pf_pos[15] == ' '))) {
            MSVCRT$free(normalized_path);
            return FALSE;
        }
    }
    
    // Exclude AppData directories inside Users
    if (MSVCRT$strstr(normalized_path, ":\\Users") && MSVCRT$strstr(normalized_path, "\\AppData")) {
        MSVCRT$free(normalized_path);
        return FALSE;
    }
    
    MSVCRT$free(normalized_path);
    return TRUE;
}

// Check if file matches date filter
BOOL MatchesDateFilter(const FILETIME* filetime, SearchOptions* opts) {
    if (!opts->has_date_filter) {
        return TRUE;
    }

    SYSTEMTIME st;
    KERNEL32$FileTimeToSystemTime(filetime, &st);

    if (opts->before_date.wYear != 0) {
        // Before date: file date must be before before_date
        if (st.wYear > opts->before_date.wYear) return FALSE;
        if (st.wYear == opts->before_date.wYear && st.wMonth > opts->before_date.wMonth) return FALSE;
        if (st.wYear == opts->before_date.wYear && st.wMonth == opts->before_date.wMonth && st.wDay >= opts->before_date.wDay) return FALSE;
        return TRUE;
    }

    if (opts->after_date.wYear != 0) {
        // After date: file date must be after after_date
        if (st.wYear < opts->after_date.wYear) return FALSE;
        if (st.wYear == opts->after_date.wYear && st.wMonth < opts->after_date.wMonth) return FALSE;
        if (st.wYear == opts->after_date.wYear && st.wMonth == opts->after_date.wMonth && st.wDay <= opts->after_date.wDay) return FALSE;
        return TRUE;
    }

    return TRUE;
}

// Search for keywords in file contents
BOOL SearchFileContents(const char* filepath, SearchOptions* opts) {
    if (!opts->search_contents || opts->keyword_count == 0) {
        return FALSE;
    }

    HANDLE hFile = KERNEL32$CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    // Get file size
    DWORD fileSizeHigh = 0;
    DWORD fileSize = KERNEL32$GetFileSize(hFile, &fileSizeHigh);
    ULONGLONG totalSize = ((ULONGLONG)fileSizeHigh << 32) | fileSize;
    
    // Check if file is too large
    if (totalSize > MAX_CONTENT_BUFFER_SIZE || totalSize == 0) {
        KERNEL32$CloseHandle(hFile);
        return FALSE;
    }

    // Allocate buffer
    char* buffer = (char*)MSVCRT$malloc((size_t)totalSize + 1);
    if (!buffer) {
        KERNEL32$CloseHandle(hFile);
        return FALSE;
    }

    // Read file
    DWORD bytesRead = 0;
    if (!KERNEL32$ReadFile(hFile, buffer, (DWORD)totalSize, &bytesRead, NULL)) {
        MSVCRT$free(buffer);
        KERNEL32$CloseHandle(hFile);
        return FALSE;
    }
    
    buffer[bytesRead] = '\0';
    KERNEL32$CloseHandle(hFile);

    // Convert to lowercase for case-insensitive search
    for (DWORD i = 0; i < bytesRead; i++) {
        buffer[i] = (char)MSVCRT$tolower((unsigned char)buffer[i]);
    }

    // Search for keywords
    BOOL found = FALSE;
    for (int i = 0; i < opts->keyword_count; i++) {
        // Convert keyword to lowercase
        size_t keywordLen = MSVCRT$strlen(opts->keywords[i]);
        char* lowerKeyword = (char*)MSVCRT$malloc(keywordLen + 1);
        if (!lowerKeyword) continue;
        
        for (size_t j = 0; j < keywordLen; j++) {
            lowerKeyword[j] = (char)MSVCRT$tolower((unsigned char)opts->keywords[i][j]);
        }
        lowerKeyword[keywordLen] = '\0';

        // Simple substring search (wildcards not supported in content search for now)
        // Remove wildcards for content search
        char* searchPattern = lowerKeyword;
        size_t patternLen = MSVCRT$strlen(searchPattern);
        if (patternLen > 0 && searchPattern[patternLen - 1] == '*') {
            searchPattern[patternLen - 1] = '\0';
            patternLen--;
        }

        if (patternLen > 0) {
            const char* match = MSVCRT$strstr(buffer, searchPattern);
            if (match) {
                found = TRUE;
                // Normalize path before output (remove double backslashes)
                char* normalized_filepath = (char*)MSVCRT$malloc(MSVCRT$strlen(filepath) + 1);
                if (normalized_filepath) {
                    MSVCRT$memcpy(normalized_filepath, filepath, MSVCRT$strlen(filepath) + 1);
                    NormalizePath(normalized_filepath);
                    
                    // Extract context around match
                    const char* start = match - CONTEXT_BUFFER_SIZE;
                    if (start < buffer) start = buffer;
                    const char* end = match + patternLen + CONTEXT_BUFFER_SIZE;
                    if (end > buffer + bytesRead) end = buffer + bytesRead;
                    
                    size_t contextLen = end - start;
                    char* context = (char*)MSVCRT$malloc(contextLen + 1);
                    if (context) {
                        MSVCRT$memcpy(context, start, contextLen);
                        context[contextLen] = '\0';
                        BeaconPrintf(CALLBACK_OUTPUT, "[+] %s:\n\t ...%s...\n", normalized_filepath, context);
                        MSVCRT$free(context);
                    } else {
                        BeaconPrintf(CALLBACK_OUTPUT, "[+] %s\n", normalized_filepath);
                    }
                    MSVCRT$free(normalized_filepath);
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[+] %s\n", filepath);
                }
                break; // Only report first match
            }
        }

        MSVCRT$free(lowerKeyword);
    }

    MSVCRT$free(buffer);
    return found;
}

// Recursive file search
void SearchDirectory(const char* dir_path, SearchOptions* opts) {
    WIN32_FIND_DATAA findData;
    HANDLE hFind;
    char search_path[MAX_PATH_LENGTH + 4];
    char file_path[MAX_PATH_LENGTH];

    // Check if we've reached max results
    if (opts->result_count >= MAX_RESULTS) {
        return;
    }

    // Build search path with bounds checking
    if (MSVCRT$strlen(dir_path) > MAX_PATH_LENGTH - 3) {
        // Silently skip directories with paths too long
        return;
    }
    MSVCRT$_snprintf(search_path, sizeof(search_path), "%s\\*", dir_path);

    hFind = KERNEL32$FindFirstFileA(search_path, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD error = KERNEL32$GetLastError();
        // Only report errors that are not common noise
        if (error != ERROR_ACCESS_DENIED && error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Cannot access directory %s (Error: %lu)\n", dir_path, error);
        }
        return;
    }

    do {
        // Check result limit
        if (opts->result_count >= MAX_RESULTS) {
            break;
        }

        // Skip . and ..
        if (MSVCRT$strcmp(findData.cFileName, ".") == 0 || 
            MSVCRT$strcmp(findData.cFileName, "..") == 0) {
            continue;
        }

        // Build full path with bounds checking
        if (MSVCRT$strlen(dir_path) + MSVCRT$strlen(findData.cFileName) + 2 > MAX_PATH_LENGTH) {
            // Silently skip files with paths too long
            continue;
        }
        MSVCRT$_snprintf(file_path, sizeof(file_path), "%s\\%s", dir_path, findData.cFileName);

        // Check if it's a directory
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (IsFolderValid(file_path, opts)) {
                SearchDirectory(file_path, opts);
            }
            continue;
        }

        // Check file extension
        if (!MatchesFiletype(file_path, opts)) {
            continue;
        }

        // Check file size
        ULONGLONG file_size = ((ULONGLONG)findData.nFileSizeHigh << 32) | findData.nFileSizeLow;
        ULONGLONG file_size_kb = file_size / 1024;
        if (file_size_kb > opts->max_file_size_kb && opts->search_contents) {
            continue;
        }

        // Check date filter
        if (!MatchesDateFilter(&findData.ftLastWriteTime, opts)) {
            continue;
        }

        // Check if filename matches keyword
        // If no keywords specified, match all files by name
        BOOL nameMatch = (opts->keyword_count == 0) ? TRUE : MatchesKeyword(findData.cFileName, opts);
        // If strict VBA macro check is enabled (-v), only report Office files that actually contain VBA (OOXML only here)
        if (opts->check_for_macro) {
            if (!CheckForVBAMacrosStrict(file_path, FALSE)) {
                continue;
            }
        }

        if (nameMatch) {
            // Normalize path before output (remove double backslashes)
            NormalizePath(file_path);
            BeaconPrintf(CALLBACK_OUTPUT, "[+] %s\n", file_path);
            opts->result_count++;
        }

        // If searching contents, also search in file contents (for all files, not just name matches)
        if (opts->search_contents) {
            if (SearchFileContents(file_path, opts)) {
                // Only count if not already found by name
                if (!nameMatch) {
                    opts->result_count++;
                }
            }
        }

    } while (KERNEL32$FindNextFileA(hFind, &findData));

    KERNEL32$FindClose(hFind);
}

// Trim quotes from beginning and end of string (in-place)
void TrimQuotes(char* str) {
    if (!str || MSVCRT$strlen(str) == 0) return;
    
    size_t len = MSVCRT$strlen(str);
    size_t start = 0;
    size_t end = len;
    
    // Remove leading quotes
    while (start < len && (str[start] == '\'' || str[start] == '\"')) {
        start++;
    }
    
    // Remove trailing quotes
    while (end > start && (str[end - 1] == '\'' || str[end - 1] == '\"')) {
        end--;
    }
    
    // Shift string if needed
    if (start > 0) {
        size_t i;
        for (i = 0; i < (end - start); i++) {
            str[i] = str[start + i];
        }
        str[i] = '\0';
    } else if (end < len) {
        str[end] = '\0';
    }
}

// Normalize path by replacing double backslashes with single ones
void NormalizePath(char* path) {
    if (!path || MSVCRT$strlen(path) == 0) return;
    
    int write_pos = 0;
    for (int read_pos = 0; path[read_pos]; read_pos++) {
        if (path[read_pos] == '\\' && path[read_pos + 1] == '\\') {
            // Skip double backslash, write only one
            path[write_pos++] = '\\';
            read_pos++; // Skip the second backslash
        } else {
            path[write_pos++] = path[read_pos];
        }
    }
    path[write_pos] = '\0';
}

// Parse comma-separated list
void ParseCSVList(char* str, char*** list, int* count) {
    if (!str || MSVCRT$strlen(str) == 0) {
        *list = NULL;
        *count = 0;
        return;
    }

    // Count items
    int item_count = 1;
    for (int i = 0; str[i]; i++) {
        if (str[i] == ',') item_count++;
    }

    *list = (char**)MSVCRT$malloc(sizeof(char*) * item_count);
    *count = item_count;

    // Create a copy since strtok modifies the string
    size_t len = MSVCRT$strlen(str);
    char* str_copy = (char*)MSVCRT$malloc(len + 1);
    if (!str_copy) {
        MSVCRT$free(*list);
        *list = NULL;
        *count = 0;
        return;
    }
    MSVCRT$memcpy(str_copy, str, len + 1);

    // Parse items
    char* token = MSVCRT$strtok(str_copy, ",");
    int idx = 0;
    while (token && idx < item_count) {
        // Trim whitespace
        while (*token == ' ') token++;
        char* end = token + MSVCRT$strlen(token) - 1;
        while (end > token && *end == ' ') *end-- = '\0';
        
        // Trim quotes
        TrimQuotes(token);
        
        // Normalize path (replace double backslashes with single ones)
        NormalizePath(token);

        // Copy the token
        size_t token_len = MSVCRT$strlen(token);
        (*list)[idx] = (char*)MSVCRT$malloc(token_len + 1);
        if ((*list)[idx]) {
            MSVCRT$memcpy((*list)[idx], token, token_len + 1);
            idx++;
        }
        token = MSVCRT$strtok(NULL, ",");
    }
    *count = idx;
    
    MSVCRT$free(str_copy);
}

// Parse date string (dd.MM.yyyy - Russian format)
BOOL ParseDate(const char* date_str, SYSTEMTIME* st) {
    if (MSVCRT$strlen(date_str) != 10) return FALSE;
    if (date_str[2] != '.' || date_str[5] != '.') return FALSE;

    // Russian format: dd.MM.yyyy
    st->wDay = (WORD)((date_str[0] - '0') * 10 + (date_str[1] - '0'));
    st->wMonth = (WORD)((date_str[3] - '0') * 10 + (date_str[4] - '0'));
    st->wYear = (WORD)((date_str[6] - '0') * 1000 + (date_str[7] - '0') * 100 + 
                       (date_str[8] - '0') * 10 + (date_str[9] - '0'));
    st->wDayOfWeek = 0;
    st->wHour = 0;
    st->wMinute = 0;
    st->wSecond = 0;
    st->wMilliseconds = 0;

    return (st->wYear >= 1900 && st->wYear <= 9999 && 
            st->wMonth >= 1 && st->wMonth <= 12 && 
            st->wDay >= 1 && st->wDay <= 31);
}

void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    // New: raw cmdline for flag validation
    char* raw_cmdline = BeaconDataExtract(&parser, NULL);

    SearchOptions opts = {0};
    opts.max_file_size_kb = 1024; // Default 1MB
    opts.system_dirs = FALSE;
    opts.search_contents = FALSE;
    opts.check_for_macro = FALSE;
    opts.has_date_filter = FALSE;
    opts.result_count = 0;

    // Validate flags from raw_cmdline against whitelist
    if (raw_cmdline && MSVCRT$strlen(raw_cmdline) > 0) {
        const char* p = raw_cmdline;
        while (*p) {
            if (*p == '-') {
                const char* start = p;
                p++;
                const char* f = p;
                while (*p && *p != ' ' && *p != '\t') p++;
                size_t flen = (size_t)(p - start);
                // Copy flag token
                if (flen > 0 && flen < 64) {
                    char flag[64];
                    for (size_t i = 0; i < flen && i < 63; i++) flag[i] = start[i];
                    flag[(flen < 63 ? flen : 63)] = '\0';
                    // Whitelist: -d -f -k -c -m -s -b -a -v
                    BOOL ok = FALSE;
                    if (MSVCRT$strncmp(flag, "-d", 2) == 0 || MSVCRT$strncmp(flag, "-f", 2) == 0 || MSVCRT$strncmp(flag, "-k", 2) == 0 ||
                        MSVCRT$strncmp(flag, "-c", 2) == 0 || MSVCRT$strncmp(flag, "-m", 2) == 0 || MSVCRT$strncmp(flag, "-s", 2) == 0 ||
                        MSVCRT$strncmp(flag, "-b", 2) == 0 || MSVCRT$strncmp(flag, "-a", 2) == 0 || MSVCRT$strncmp(flag, "-v", 2) == 0) {
                        ok = TRUE;
                    }
                    if (!ok) {
                        BeaconPrintf(CALLBACK_ERROR, "Invalid flag: %s\n", flag);
                        return; // Abort execution on unknown flag
                    }
                }
            } else {
                p++;
            }
        }
    }

    // Parse arguments
    char* directories_str = BeaconDataExtract(&parser, NULL);
    char* filetypes_str = BeaconDataExtract(&parser, NULL);
    char* keywords_str = BeaconDataExtract(&parser, NULL);
    int search_contents_int = BeaconDataInt(&parser);
    int max_filesize_int = BeaconDataInt(&parser);
    int system_dirs_int = BeaconDataInt(&parser);
    char* before_date_str = BeaconDataExtract(&parser, NULL);
    char* after_date_str = BeaconDataExtract(&parser, NULL);
    int check_macro_int = BeaconDataInt(&parser);

    opts.search_contents = (search_contents_int != 0);
    opts.system_dirs = (system_dirs_int != 0);
    opts.check_for_macro = (check_macro_int != 0);
    if (max_filesize_int > 0) {
        opts.max_file_size_kb = (ULONGLONG)max_filesize_int;
    }

    // Parse CSV lists
    if (directories_str && MSVCRT$strlen(directories_str) > 0) {
        ParseCSVList(directories_str, &opts.directories, &opts.dir_count);
    } else {
        // Default: C:\ drive only
        opts.dir_count = 1;
        opts.directories = (char**)MSVCRT$malloc(sizeof(char*) * 1);
        opts.directories[0] = (char*)MSVCRT$malloc(4);
        MSVCRT$memcpy(opts.directories[0], "C:\\", 4);
    }

    if (filetypes_str && MSVCRT$strlen(filetypes_str) > 0) {
        ParseCSVList(filetypes_str, &opts.filetypes, &opts.filetype_count);
    } else {
        // If -v (strict macro check) is enabled and no filetypes provided,
        // default to Office formats. Otherwise keep generic defaults.
        if (opts.check_for_macro) {
            opts.filetype_count = 4;
            opts.filetypes = (char**)MSVCRT$malloc(sizeof(char*) * 4);
            opts.filetypes[0] = (char*)MSVCRT$malloc(5);
            opts.filetypes[1] = (char*)MSVCRT$malloc(5);
            opts.filetypes[2] = (char*)MSVCRT$malloc(6);
            opts.filetypes[3] = (char*)MSVCRT$malloc(6);
            MSVCRT$memcpy(opts.filetypes[0], ".doc", 5);
            MSVCRT$memcpy(opts.filetypes[1], ".xls", 5);
            MSVCRT$memcpy(opts.filetypes[2], ".docm", 6);
            MSVCRT$memcpy(opts.filetypes[3], ".xlsm", 6);
        } else {
            // Default: .txt and .docx
            opts.filetype_count = 2;
            opts.filetypes = (char**)MSVCRT$malloc(sizeof(char*) * 2);
            opts.filetypes[0] = (char*)MSVCRT$malloc(5);
            opts.filetypes[1] = (char*)MSVCRT$malloc(6);
            MSVCRT$memcpy(opts.filetypes[0], ".txt", 5);
            MSVCRT$memcpy(opts.filetypes[1], ".docx", 6);
        }
    }

    if (keywords_str && MSVCRT$strlen(keywords_str) > 0) {
        ParseCSVList(keywords_str, &opts.keywords, &opts.keyword_count);
    } else {
        // No keywords specified - match all filenames when searching by extension
        opts.keyword_count = 0;
        opts.keywords = NULL;
    }

    // Parse dates
    if (before_date_str && MSVCRT$strlen(before_date_str) > 0) {
        if (!ParseDate(before_date_str, &opts.before_date)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Invalid before date format: %s (expected: yyyy-MM-dd)\n", before_date_str);
        } else {
            opts.has_date_filter = TRUE;
        }
    }

    if (after_date_str && MSVCRT$strlen(after_date_str) > 0) {
        if (!ParseDate(after_date_str, &opts.after_date)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Invalid after date format: %s (expected: yyyy-MM-dd)\n", after_date_str);
        } else {
            opts.has_date_filter = TRUE;
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting SauronEye search...\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Directories: ");
    for (int i = 0; i < opts.dir_count; i++) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s ", opts.directories[i]);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "\n");

    // Search each directory
    for (int i = 0; i < opts.dir_count; i++) {
        if (opts.result_count >= MAX_RESULTS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Reached maximum results limit (%d)\n", MAX_RESULTS);
            break;
        }
        if (SHLWAPI$PathFileExistsA(opts.directories[i])) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Searching in: %s\n", opts.directories[i]);
            SearchDirectory(opts.directories[i], &opts);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] Directory does not exist: %s\n", opts.directories[i]);
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Search completed. Found %d results.\n", opts.result_count);
}

