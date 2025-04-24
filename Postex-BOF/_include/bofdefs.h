#pragma once
/* some code and/or ideas are from trustedsec SA Github repo -- thankyou trustedsec! */
#include <windows.h>
#include <gdiplus.h>

#ifdef BOF

#ifdef __cplusplus
extern "C" {
#endif

#include "../_include/beacon.h"

void go(char* buff, int len);


/* 7/2/2025 update*/

DECLSPEC_IMPORT int WINAPI MSVCRT$fclose(FILE* stream);
#define fclose    MSVCRT$fclose

DECLSPEC_IMPORT FILE* WINAPI MSVCRT$fopen(const char* filename, const char* mode);
#define fopen     MSVCRT$fopen

DECLSPEC_IMPORT size_t WINAPI MSVCRT$fwrite(const void* ptr, size_t size, size_t count, FILE* stream);
#define fwrite    MSVCRT$fwrite

DECLSPEC_IMPORT BOOL WINAPI User32$ShowWindow(HWND hWnd, int nCmdShow);
#define ShowWindow User32$ShowWindow

DECLSPEC_IMPORT BOOL WINAPI User32$PrintWindow(HWND hWnd, HDC hdcBlt, UINT nFlags);
#define PrintWindow User32$PrintWindow

DECLSPEC_IMPORT BOOL WINAPI User32$SetLayeredWindowAttributes(HWND hwnd, COLORREF crKey, BYTE bAlpha, DWORD dwFlags);
#define SetLayeredWindowAttributes User32$SetLayeredWindowAttributes

DECLSPEC_IMPORT BOOL WINAPI User32$SetWindowPos(HWND hWnd, HWND hWndInsertAfter, int X, int Y, int cx, int cy, UINT uFlags);
#define SetWindowPos User32$SetWindowPos

DECLSPEC_IMPORT BOOL WINAPI User32$GetWindowPlacement(HWND hWnd, WINDOWPLACEMENT* lpwndpl);
#define GetWindowPlacement User32$GetWindowPlacement

DECLSPEC_IMPORT BOOL WINAPI User32$IsWindowVisible(HWND hWnd);
#define IsWindowVisible User32$IsWindowVisible

DECLSPEC_IMPORT BOOL WINAPI User32$UpdateWindow(HWND hWnd);
#define UpdateWindow User32$UpdateWindow

DECLSPEC_IMPORT BOOL WINAPI User32$GetWindowRect(HWND hWnd, LPRECT lpRect);
#define GetWindowRect User32$GetWindowRect

DECLSPEC_IMPORT LONG WINAPI User32$GetWindowLongA(HWND hWnd, int nIndex);
#define GetWindowLongA User32$GetWindowLongA

DECLSPEC_IMPORT LONG WINAPI User32$SetWindowLongA(HWND hWnd, int nIndex, LONG dwNewLong);
#define SetWindowLongA User32$SetWindowLongA

DECLSPEC_IMPORT BOOL WINAPI User32$EnumWindows(WNDENUMPROC lpEnumFunc, LPARAM lParam);

DECLSPEC_IMPORT DWORD WINAPI User32$GetWindowThreadProcessId(HWND hWnd, LPDWORD lpdwProcessId);
#define GetWindowThreadProcessId User32$GetWindowThreadProcessId


/* resolve some extra funcs for the screenshot */


    DECLSPEC_IMPORT DWORD WINAPI User32$MessageBoxA(HWND, LPCTSTR, LPCTSTR, UINT);
#define MessageBoxCustom User32$MessageBoxA

    DECLSPEC_IMPORT int WINAPI User32$GetSystemMetrics(int nIndex);
#define GetSystemMetrics User32$GetSystemMetrics

    DECLSPEC_IMPORT BOOL WINAPI User32$SetProcessDPIAware();
#define SetProcessDPIAware User32$SetProcessDPIAware

    DECLSPEC_IMPORT HDC WINAPI User32$GetDC(HWND hWnd);
#define GetDC User32$GetDC

    DECLSPEC_IMPORT HDC WINAPI GDI32$CreateCompatibleDC(HDC hdc);
#define CreateCompatibleDC GDI32$CreateCompatibleDC

    DECLSPEC_IMPORT HBITMAP WINAPI GDI32$CreateCompatibleBitmap(HDC hdc, int cx, int cy);
#define CreateCompatibleBitmap GDI32$CreateCompatibleBitmap

    DECLSPEC_IMPORT HGDIOBJ WINAPI GDI32$SelectObject(HDC hdc, HGDIOBJ h);
#define SelectObject GDI32$SelectObject

    DECLSPEC_IMPORT BOOL WINAPI GDI32$BitBlt(HDC   hdc,
        int   x,
        int   y,
        int   cx,
        int   cy,
        HDC   hdcSrc,
        int   x1,
        int   y1,
        DWORD rop);
#define BitBlt GDI32$BitBlt

    DECLSPEC_IMPORT BOOL WINAPI User32$OpenClipboard(HWND hWndNewOwner);
#define OpenClipboard User32$OpenClipboard

    DECLSPEC_IMPORT BOOL WINAPI User32$EmptyClipboard();
#define EmptyClipboard User32$EmptyClipboard

    DECLSPEC_IMPORT BOOL WINAPI User32$SetClipboardData(UINT uFormat, HANDLE hMem);
#define SetClipboardData User32$SetClipboardData

    DECLSPEC_IMPORT BOOL WINAPI User32$CloseClipboard();
#define CloseClipboard User32$CloseClipboard

    DECLSPEC_IMPORT BOOL WINAPI GDI32$DeleteDC(HDC hdc);
#define DeleteDC GDI32$DeleteDC

    DECLSPEC_IMPORT int WINAPI User32$ReleaseDC(HWND hWnd, HDC  hDC);
#define ReleaseDC User32$ReleaseDC

    DECLSPEC_IMPORT HGDIOBJ WINAPI GDI32$DeleteObject(HGDIOBJ ho);
#define DeleteObject GDI32$DeleteObject



    /* End of function resolutions for screenshot */

    /* Resolve some functions for writing BMP to disk*/

    DECLSPEC_IMPORT HDC WINAPI GDI32$CreateDCA(LPCSTR         pwszDriver,
        LPCSTR         pwszDevice,
        LPCSTR         pszPort,
        const DEVMODEA* pdm);
#define CreateDCA GDI32$CreateDCA

    DECLSPEC_IMPORT int WINAPI GDI32$GetDeviceCaps(HDC hdc,
        int index);
#define GetDeviceCaps GDI32$GetDeviceCaps

    DECLSPEC_IMPORT int WINAPI GDI32$GetObjectA(HANDLE h,
        int    c,
        LPVOID pv);
#define GetObjectA GDI32$GetObjectA
    DECLSPEC_IMPORT HGLOBAL WINAPI KERNEL32$GlobalAlloc(
        UINT   uFlags,
        SIZE_T dwBytes);
#define GlobalAlloc KERNEL32$GlobalAlloc

    DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$GlobalLock(HGLOBAL);
#define GlobalLock KERNEL32$GlobalLock

    DECLSPEC_IMPORT WINGDIAPI HGDIOBJ WINAPI GDI32$GetStockObject(int);
#define GetStockObject GDI32$GetStockObject

    DECLSPEC_IMPORT WINGDIAPI HPALETTE WINAPI GDI32$SelectPalette(HDC, HPALETTE, BOOL);
#define SelectPalette GDI32$SelectPalette

    DECLSPEC_IMPORT WINGDIAPI UINT WINAPI GDI32$RealizePalette(HDC);
#define RealizePalette GDI32$RealizePalette

    DECLSPEC_IMPORT WINGDIAPI int WINAPI GDI32$GetDIBits(HDC          hdc,
        HBITMAP      hbm,
        UINT         start,
        UINT         cLines,
        LPVOID       lpvBits,
        LPBITMAPINFO lpbmi,
        UINT         usage);
#define GetDIBits GDI32$GetDIBits

    DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$GlobalUnlock(HGLOBAL);
#define GlobalUnlock KERNEL32$GlobalUnlock

    DECLSPEC_IMPORT WINBASEAPI HGLOBAL WINAPI KERNEL32$GlobalFree(HGLOBAL);
#define GlobalFree KERNEL32$GlobalFree

    DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
#define CloseHandle KERNEL32$CloseHandle




    /* End of function resolutions for writing BMP to disk */


/* COM */
DECLSPEC_IMPORT HRESULT  WINAPI   OLE32$CLSIDFromString(LPCWSTR, LPCLSID);
DECLSPEC_IMPORT HRESULT  WINAPI   OLE32$CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID* ppv);
DECLSPEC_IMPORT HRESULT  WINAPI   OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT VOID     WINAPI   OLE32$CoUninitialize();
DECLSPEC_IMPORT HRESULT  WINAPI   OLE32$IIDFromString(LPWSTR lpsz, LPIID lpiid);
DECLSPEC_IMPORT HRESULT	 WINAPI	  OLE32$CoInitialize(LPVOID pvReserved);
DECLSPEC_IMPORT HRESULT	 WINAPI   OLE32$CoCreateInstanceEx(REFCLSID, IUnknown*, DWORD, COSERVERINFO*, DWORD, MULTI_QI*);
DECLSPEC_IMPORT BSTR	 WINAPI	  OleAut32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT LPVOID	 WINAPI	  OLEAUT32$VariantInit(VARIANTARG* pvarg);
DECLSPEC_IMPORT HRESULT	 WINAPI	  OLE32$CoInitializeSecurity(PSECURITY_DESCRIPTOR pSecDesc, LONG cAuthSvc, SOLE_AUTHENTICATION_SERVICE* asAuthSvc, void* pReserved1, DWORD dwAuthnLevel,  DWORD dwImpLevel, void* pAuthList, DWORD dwCapabilities, void* pReserved3);

/* Registry */
DECLSPEC_IMPORT LSTATUS APIENTRY ADVAPI32$RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
DECLSPEC_IMPORT LSTATUS APIENTRY ADVAPI32$RegDeleteTreeA(HKEY hKey, LPCSTR lpSubKey);
DECLSPEC_IMPORT LSTATUS APIENTRY ADVAPI32$RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired,
	CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition);
DECLSPEC_IMPORT LSTATUS APIENTRY ADVAPI32$RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType,
	CONST BYTE* lpData, DWORD cbData);


/* FileSystem */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$SetFilePointerEx(HANDLE hFile, LARGE_INTEGER liDistanceToMove, PLARGE_INTEGER lpDistanceToMoveHigh, DWORD dwMoveMethod);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize);
DECLSPEC_IMPORT DWORD WINAPI VERSION$GetFileVersionInfoSizeW(LPCWSTR lptstrFilenamea, LPDWORD lpdwHandle);
DECLSPEC_IMPORT BOOL WINAPI VERSION$GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);
DECLSPEC_IMPORT BOOL WINAPI VERSION$VerQueryValueW(LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID* lplpBuffer, PUINT puLen);


/* Memory */
DECLSPEC_IMPORT LPVOID	WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT BOOL	WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
DECLSPEC_IMPORT LPVOID	WINAPI KERNEL32$HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
DECLSPEC_IMPORT void* __cdecl  MSVCRT$memcpy(LPVOID, LPVOID, size_t);
DECLSPEC_IMPORT void* __cdecl  MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void __cdecl   MSVCRT$memset(void*, int, size_t);


/* Process */
DECLSPEC_IMPORT HANDLE	WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT BOOL	WINAPI ADVAPI32$CreateProcessWithLogonW(LPCWSTR lpUsername, LPCWSTR lpDomain, LPCWSTR lpPassword, DWORD dwLogonFlags, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
DECLSPEC_IMPORT HANDLE	WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT SIZE_T WINAPI  KERNEL32$VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
DECLSPEC_IMPORT DWORD WINAPI   KERNEL32$GetProcessId(HANDLE Process);
DECLSPEC_IMPORT BOOL WINAPI    KERNEL32$ReadProcessMemory(HANDLE  hProcess, LPCVOID lpBaseAddress, LPVOID  lpBuffer, SIZE_T  nSize, SIZE_T* lpNumberOfBytesRead);
DECLSPEC_IMPORT VOID WINAPI    KERNEL32$Sleep(DWORD dwMilliseconds);
DECLSPEC_IMPORT HANDLE WINAPI  KERNEL32$GetCurrentProcess(VOID);
DECLSPEC_IMPORT BOOL WINAPI	   ADVAPI32$LookupPrivilegeValueW(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);
DECLSPEC_IMPORT DWORD WINAPI   PSAPI$GetModuleFileNameExW(HANDLE hProcess, HMODULE hModule, LPWSTR lpFilename, DWORD nSize);


/* GetLast Error */
DECLSPEC_IMPORT DWORD	WINAPI KERNEL32$GetLastError(VOID);


/* Directories */
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$RemoveDirectoryA(LPCSTR);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CreateDirectoryA(LPCSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$MoveFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName);
DECLSPEC_IMPORT BOOL WINAPI SHLWAPI$PathIsDirectoryA(LPCSTR);
DECLSPEC_IMPORT BOOL WINAPI SHLWAPI$PathFileExistsA(LPCSTR pszPath);


/* strings */
DECLSPEC_IMPORT PSTR WINAPI SHLWAPI$StrChrA(PCSTR pszStart, WORD wMatch);
DECLSPEC_IMPORT LPSTR	__cdecl	MSVCRT$strchr(LPSTR, int);
DECLSPEC_IMPORT errno_t __cdecl MSVCRT$strcat_s(LPSTR, size_t, LPCSTR);
DECLSPEC_IMPORT errno_t __cdecl MSVCRT$strcpy_s(LPSTR, size_t, LPCSTR);
DECLSPEC_IMPORT errno_t __cdecl MSVCRT$strncpy_s(LPSTR, size_t, LPCSTR, size_t);
DECLSPEC_IMPORT int		__cdecl	MSVCRT$_snprintf(LPSTR, size_t, LPCSTR, ...);
DECLSPEC_IMPORT void WINAPI		MSVCRT$sprintf(char*, char[], ...);
DECLSPEC_IMPORT int		__cdecl MSVCRT$_vsnprintf(LPSTR, size_t, LPCSTR, va_list);
DECLSPEC_IMPORT	size_t	__cdecl MSVCRT$wcslen(LPCWSTR);
DECLSPEC_IMPORT int __cdecl		MSVCRT$strcmp(const char* _Str1, const char* _Str2);
DECLSPEC_IMPORT size_t __cdecl		MSVCRT$strlen(const char* str);
DECLSPEC_IMPORT LPSTR WINAPI	Kernel32$lstrcpyA(LPSTR lpString1, LPCSTR lpString2);
DECLSPEC_IMPORT LPSTR WINAPI	Kernel32$lstrcatA(LPSTR lpString1, LPCSTR lpString2);
DECLSPEC_IMPORT LPSTR WINAPI	Kernel32$lstrcpynA(LPSTR lpString1, LPCSTR lpString2, int iMaxLength);
DECLSPEC_IMPORT int WINAPI		KERNEL32$lstrlenW(LPCWSTR lpString);
DECLSPEC_IMPORT LPWSTR WINAPI	KERNEL32$lstrcpyW(LPWSTR lpString1, LPCWSTR lpString2);


/* RPC */
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY Rpcrt4$RpcStringFreeA(RPC_CSTR* String);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY Rpcrt4$UuidCreate(UUID* Uuid);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY Rpcrt4$UuidToStringA(const UUID* Uuid, RPC_CSTR* StringUuid);


/* Random */
DECLSPEC_IMPORT void WINAPI MSVCRT$srand(int initial);
DECLSPEC_IMPORT int WINAPI MSVCRT$rand();


/* DateTime */
DECLSPEC_IMPORT time_t WINAPI MSVCRT$time(time_t* time);


/* SystemInfo */
DECLSPEC_IMPORT void WINAPI KERNEL32$GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$IsProcessorFeaturePresent(DWORD ProcessorFeature);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetUserNameW(LPWSTR lpBuffer, LPDWORD pcbBuffer);






#ifdef __cplusplus
}
#endif


/* helper macros */

#define malloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)	/* trustedsec */

/* 8/2/2025: THIS BROKE FOR SOME REASON */
//#define free(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (LPVOID)addr)	/* trustedsec */
/* reassigned this to the MSVCRT free */
extern "C" DECLSPEC_IMPORT void __cdecl MSVCRT$free(void* _Memory);
#define free(addr)    MSVCRT$free((void*)addr)  

#define ZeroMemory(address, size) memset(address, 0, size);

/* GDI+ for JPG stuffs */
extern "C" DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
extern "C" DECLSPEC_IMPORT HRESULT WINAPI OLE32$CreateStreamOnHGlobal(HGLOBAL hGlobal, BOOL fDeleteOnRelease, LPSTREAM * ppstm);

#define LoadLibraryA              KERNEL32$LoadLibraryA
#define CreateStreamOnHGlobal     OLE32$CreateStreamOnHGlobal


/* 7/2/2025 update - Hotfix for CS 4.9 support */
extern "C" DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
extern "C" DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
DECLSPEC_IMPORT LONG_PTR WINAPI USER32$GetWindowLongPtrA(HWND hWnd, int nIndex);
DECLSPEC_IMPORT LONG_PTR WINAPI USER32$SetWindowLongPtrA(HWND hWnd, int nIndex, LONG_PTR dwNewLong);

/* ----------------------------------- DEFINITIONS ------------------------------------------*/

/* 7/2/2025 update */
#define GetModuleHandleA         KERNEL32$GetModuleHandleA
#define GetProcAddress           KERNEL32$GetProcAddress
#define GetWindowLongPtrA        USER32$GetWindowLongPtrA
#define SetWindowLongPtrA        USER32$SetWindowLongPtrA


/* window functions */
#define ShowWindow               User32$ShowWindow
#define PrintWindow              User32$PrintWindow
#define SetLayeredWindowAttributes  User32$SetLayeredWindowAttributes
#define SetWindowPos             User32$SetWindowPos
#define GetWindowPlacement       User32$GetWindowPlacement
#define IsWindowVisible          User32$IsWindowVisible
#define UpdateWindow             User32$UpdateWindow
#define GetWindowRect            User32$GetWindowRect
#define GetWindowLongA           User32$GetWindowLongA
#define SetWindowLongA           User32$SetWindowLongA
#define EnumWindows              User32$EnumWindows
#define GetWindowThreadProcessId User32$GetWindowThreadProcessId

/* COM */
#define	CLSIDFromString			OLE32$CLSIDFromString
#define	CoCreateInstance		OLE32$CoCreateInstance
#define CoInitializeEx			OLE32$CoInitializeEx
#define CoUninitialize			OLE32$CoUninitialize
#define IIDFromString			OLE32$IIDFromString
#define CoInitialize			OLE32$CoInitialize
#define CoCreateInstanceEx		OLE32$CoCreateInstanceEx
#define SysAllocString			OleAut32$SysAllocString
#define	VariantInit				OLEAUT32$VariantInit
#define CoInitialize			OLE32$CoInitialize
#define CoInitializeSecurity	OLE32$CoInitializeSecurity

/* memory */
#define HeapFree				KERNEL32$HeapFree
#define HeapAlloc				KERNEL32$HeapAlloc
#define HeapReAlloc				KERNEL32$HeapReAlloc
#define memcpy					MSVCRT$memcpy
#define malloc				MSVCRT$malloc
#define memset					MSVCRT$memset


/* process */
#define GetProcessHeap			KERNEL32$GetProcessHeap
#define CreateProcessWithLogonW ADVAPI32$CreateProcessWithLogonW
#define OpenProcess				KERNEL32$OpenProcess
#define VirtualQueryEx			KERNEL32$VirtualQueryEx
#define GetProcessId			KERNEL32$GetProcessId
#define	ReadProcessMemory		KERNEL32$ReadProcessMemory
#define GetCurrentProcess		KERNEL32$GetCurrentProcess
#define Sleep					KERNEL32$Sleep
#define LookupPrivilegeValueW	ADVAPI32$LookupPrivilegeValueW
#define	GetModuleFileNameExW	PSAPI$GetModuleFileNameExW


/* debug */
#define EnumerateLoadedModulesW64 DBGHELP$EnumerateLoadedModulesW64
#define SymInitializeW			DBGHELP$SymInitializeW
#define SymCleanup				DBGHELP$SymCleanup


/* filesystem */
#define CreateFileA				KERNEL32$CreateFileA
#define SetFilePointer			KERNEL32$SetFilePointer
#define SetFilePointerEx		KERNEL32$SetFilePointerEx
#define WriteFile				KERNEL32$WriteFile
#define GetFileSizeEx			KERNEL32$GetFileSizeEx
#define GetFileVersionInfoSizeW	VERSION$GetFileVersionInfoSizeW
#define GetFileVersionInfoW		VERSION$GetFileVersionInfoW
#define	VerQueryValueW			VERSION$VerQueryValueW

/* error */
#define GetLastError			KERNEL32$GetLastError 


/* registry */
#define RegOpenKeyExA			ADVAPI32$RegOpenKeyExA
#define RegDeleteTreeA			ADVAPI32$RegDeleteTreeA
#define RegCreateKeyExA			ADVAPI32$RegCreateKeyExA
#define RegSetValueExA			ADVAPI32$RegSetValueExA


/* directory */
#define RemoveDirectoryA		KERNEL32$RemoveDirectoryA
#define CreateDirectoryA		KERNEL32$CreateDirectoryA
#define MoveFileA				KERNEL32$MoveFileA
#define PathIsDirectoryA		SHLWAPI$PathIsDirectoryA
#define PathFileExistsA			SHLWAPI$PathFileExistsA


/* strings */
#define strchr					MSVCRT$strchr
#define strcat_s				MSVCRT$strcat_s
#define strcpy_s				MSVCRT$strcpy_s
#define strncpy_s				MSVCRT$strncpy_s
#define snprintf				MSVCRT$_snprintf	/*beacon can't find snprintf without the preceeding '_' */
#define wcslen					MSVCRT$wcslen
#define vsnprintf				MSVCRT$vsnprintf
#define lstrlenW				KERNEL32$lstrlenW
#define lstrcpyW				KERNEL32$lstrcpyW
#define strcmp					MSVCRT$strcmp
#define lstrcpyA				Kernel32$lstrcpyA
#define	lstrcatA				Kernel32$lstrcatA
#define	lstrcpynA				Kernel32$lstrcpynA
#define lstrlenW				KERNEL32$lstrlenW
#define lstrcpyW				KERNEL32$lstrcpyW
#define sprintf					MSVCRT$sprintf
#define strlen                  MSVCRT$strlen


/* RPC */
#define RpcStringFreeA			Rpcrt4$RpcStringFreeA 
#define UuidCreate				Rpcrt4$UuidCreate
#define UuidToStringA			Rpcrt4$UuidToStringA


/* Random */
#define srand					MSVCRT$srand
#define rand					MSVCRT$rand


/* DateTime */
#define time					MSVCRT$time


/* SystemInfo */
#define GetSystemInfo			KERNEL32$GetSystemInfo
#define GetUserNameW			ADVAPI32$GetUserNameW
#define IsProcessorFeaturePresent	KERNEL32$IsProcessorFeaturePresent

#else

#endif