#pragma once
#pragma intrinsic(memcmp, memcpy, strcpy, strcmp, _stricmp, strlen)
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

//KERNEL32
WINBASEAPI void * WINAPI KERNEL32$VirtualAlloc (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI int WINAPI KERNEL32$VirtualFree (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
WINBASEAPI void * WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree (HANDLE, DWORD, PVOID);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (VOID);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileW (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA (LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI DWORD WINAPI KERNEL32$GetFileSize (HANDLE hFile, LPDWORD lpFileSizeHigh);
WINBASEAPI WINBOOL WINAPI KERNEL32$ReadFile (HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
WINBASEAPI WINBOOL WINAPI KERNEL32$WriteFile (HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
WINBASEAPI DWORD WINAPI KERNEL32$SetFilePointer (HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
WINBASEAPI WINBOOL WINAPI KERNEL32$GetFileInformationByHandle (HANDLE hFile, LPBY_HANDLE_FILE_INFORMATION lpFileInformation);
WINBASEAPI DWORD WINAPI KERNEL32$GetFullPathNameW (LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR *lpFilePart);
WINBASEAPI int WINAPI KERNEL32$WideCharToMultiByte (UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
WINBASEAPI int WINAPI KERNEL32$MultiByteToWideChar (UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
WINBASEAPI DWORD WINAPI KERNEL32$GetFileAttributesW (LPCWSTR lpFileName);
WINBASEAPI WINBOOL WINAPI KERNEL32$CreateDirectoryW (LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
WINBASEAPI int WINAPI KERNEL32$lstrlenW (LPCWSTR lpString);
WINBASEAPI WINBOOL WINAPI KERNEL32$GetComputerNameA (LPSTR lpBuffer, LPDWORD nSize);
WINBASEAPI WINBOOL WINAPI KERNEL32$DeviceIoControl (HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped);

#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)
#define intZeroMemory(addr,size) MSVCRT$memset((addr),0,size)

//MSVCRT
WINBASEAPI void *__cdecl MSVCRT$memcpy(void * __restrict__ _Dst,const void * __restrict__ _Src,size_t _MaxCount);
WINBASEAPI int __cdecl MSVCRT$memcmp(const void *_Buf1,const void *_Buf2,size_t _Size);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI int __cdecl MSVCRT$sprintf(char *__stream, const char *__format, ...);
WINBASEAPI int __cdecl MSVCRT$vsnprintf(char * __restrict__ d,size_t n,const char * __restrict__ format,va_list arg);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *_Str);
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char *_Str1,const char *_Str2);
DECLSPEC_IMPORT char * __cdecl MSVCRT$strcpy(char * __restrict__ __dst, const char * __restrict__ __src);
DECLSPEC_IMPORT char * __cdecl MSVCRT$strrchr(const char *_Str, int _Ch);
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t _NumOfElements, size_t _SizeOfElements);
WINBASEAPI void __cdecl MSVCRT$free(void *_Memory);

//NTDLL
WINBASEAPI NTSTATUS NTAPI NTDLL$NtCreateFile(PHANDLE FileHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,PIO_STATUS_BLOCK IoStatusBlock,PLARGE_INTEGER AllocationSize,ULONG FileAttributes,ULONG ShareAccess,ULONG CreateDisposition,ULONG CreateOptions,PVOID EaBuffer,ULONG EaLength);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtClose(HANDLE Handle);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtReadFile(HANDLE FileHandle,HANDLE Event,PIO_APC_ROUTINE ApcRoutine,PVOID ApcContext,PIO_STATUS_BLOCK IoStatusBlock,PVOID Buffer,ULONG Length,PLARGE_INTEGER ByteOffset,PULONG Key);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtWriteFile(HANDLE FileHandle,HANDLE Event,PIO_APC_ROUTINE ApcRoutine,PVOID ApcContext,PIO_STATUS_BLOCK IoStatusBlock,PVOID Buffer,ULONG Length,PLARGE_INTEGER ByteOffset,PULONG Key);
WINBASEAPI VOID NTAPI NTDLL$RtlInitUnicodeString(PUNICODE_STRING DestinationString,PCWSTR SourceString);
WINBASEAPI VOID NTAPI NTDLL$RtlZeroMemory(PVOID Destination,SIZE_T Length);

