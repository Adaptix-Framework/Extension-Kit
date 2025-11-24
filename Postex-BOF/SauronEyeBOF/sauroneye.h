#ifndef SAURONEYE_H
#define SAURONEYE_H

#include <windows.h>
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

// API declarations
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileAttributesW(LPCWSTR lpFileName);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindClose(HANDLE hFindFile);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileAttributesA(LPCSTR lpFileName);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GetFileAttributesExA(LPCSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation);
#ifndef GetFileExInfoStandard
#define GetFileExInfoStandard 0
#endif
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FileTimeToSystemTime(const FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT BOOL WINAPI SHLWAPI$PathFileExistsA(LPCSTR pszPath);
DECLSPEC_IMPORT int WINAPI MSVCRT$sprintf(char *str, const char *format, ...);
DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char *str, size_t size, const char *format, ...);
DECLSPEC_IMPORT void* WINAPI MSVCRT$malloc(size_t size);
DECLSPEC_IMPORT void* WINAPI MSVCRT$realloc(void *ptr, size_t size);
DECLSPEC_IMPORT void WINAPI MSVCRT$free(void *ptr);
DECLSPEC_IMPORT int WINAPI MSVCRT$strcmp(const char *s1, const char *s2);
DECLSPEC_IMPORT int WINAPI MSVCRT$strncmp(const char *s1, const char *s2, size_t n);
DECLSPEC_IMPORT char* WINAPI MSVCRT$strstr(const char *haystack, const char *needle);
DECLSPEC_IMPORT char* WINAPI MSVCRT$strrchr(const char *s, int c);
DECLSPEC_IMPORT char* WINAPI MSVCRT$strtok(char *str, const char *delim);
DECLSPEC_IMPORT size_t WINAPI MSVCRT$strlen(const char *s);
DECLSPEC_IMPORT int WINAPI MSVCRT$tolower(int c);
DECLSPEC_IMPORT int __cdecl MSVCRT$_stricmp(const char *s1, const char *s2);
DECLSPEC_IMPORT int __cdecl MSVCRT$_strnicmp(const char *s1, const char *s2, size_t n);
DECLSPEC_IMPORT void* WINAPI MSVCRT$memcpy(void *dest, const void *src, size_t n);
DECLSPEC_IMPORT int WINAPI MSVCRT$memcmp(const void *s1, const void *s2, size_t n);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFullPathNameA(LPCSTR lpFileName, DWORD nBufferLength, LPSTR lpBuffer, LPSTR* lpFilePart);

// NT Native API types
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

// OLE32 constants
#ifndef S_OK
#define S_OK 0x00000000
#endif

#ifndef STGM_READ
#define STGM_READ 0x00000000L
#endif

#ifndef STGM_SHARE_DENY_WRITE
#define STGM_SHARE_DENY_WRITE 0x00000020L
#endif

// Dynamic OLE32 function pointer types
typedef HRESULT (WINAPI *PFN_StgIsStorageFile)(LPCWSTR);
typedef HRESULT (WINAPI *PFN_StgOpenStorage)(LPCWSTR, void*, DWORD, void*, DWORD, void**);

// Constants
#define OOXML_SCAN_WINDOW (256 * 1024) // 256KB head/tail scan
#define MAX_RESULTS 1000
#define MAX_PATH_LENGTH 260
#define MAX_CONTENT_BUFFER_SIZE (10 * 1024 * 1024)
#define CONTEXT_BUFFER_SIZE 50

// Wildcard search performance limits (adjustable)
#define WILDCARD_MAX_MATCH_ATTEMPTS 1000        // Maximum number of pattern matching attempts
#define WILDCARD_MAX_SEARCH_SIZE (200 * 1024)  // Maximum search area for large files (200KB)
#define WILDCARD_MAX_BACKTRACK 1000             // Maximum backtracking operations to prevent infinite loops
#define MAX_MATCHES_PER_FILE 100                // Maximum matches per file to prevent excessive output

// Search options structure
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
    BOOL show_date;        // -D: Show file modification date in output
    int result_count;      // Total number of matches found
    int file_count;        // Total number of files with matches
    // Wildcard search performance tuning (0 = use default)
    int wildcard_max_attempts;      // -W: Maximum pattern matching attempts (default: WILDCARD_MAX_MATCH_ATTEMPTS)
    ULONGLONG wildcard_max_size;    // -S: Maximum search area in bytes (default: WILDCARD_MAX_SEARCH_SIZE)
    int wildcard_max_backtrack;     // -B: Maximum backtracking operations (default: WILDCARD_MAX_BACKTRACK)
    // Path deduplication
    char** seen_paths;      // Array of canonical paths already output
    int seen_paths_count;   // Number of paths in seen_paths array
    int seen_paths_capacity; // Capacity of seen_paths array
} SearchOptions;

// VBA macro detection
BOOL CheckForVBAMacrosStrict(const char* filepath, BOOL use_ole);

// Matching functions
BOOL MatchWildcard(const char* pattern, const char* str);
BOOL MatchesKeyword(const char* filename, SearchOptions* opts);
BOOL MatchesFiletype(const char* filepath, SearchOptions* opts);
BOOL IsFolderValid(const char* path, SearchOptions* opts);
BOOL MatchesDateFilter(const FILETIME* filetime, SearchOptions* opts);

// Search functions
int SearchFileContents(const char* filepath, const FILETIME* filetime, SearchOptions* opts);  // Returns number of matches found
void SearchDirectory(const char* dir_path, SearchOptions* opts);

// Utility functions
void TrimQuotes(char* str);
void NormalizePath(char* path);
void ParseCSVList(char* str, char*** list, int* count);
BOOL ParseDate(const char* date_str, SYSTEMTIME* st);
BOOL IsPathAlreadySeen(const char* filepath, SearchOptions* opts);
void AddPathToSeen(const char* filepath, SearchOptions* opts);
void GetCanonicalPath(const char* filepath, char* canonical, size_t canonicalSize);

#endif // SAURONEYE_H
