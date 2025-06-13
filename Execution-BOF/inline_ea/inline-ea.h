#include <windows.h>
#include <mscoree.h>
#include <stdio.h>
#include <unknwnbase.h>
#include <psapi.h>
#include <string.h>
#include "metahost.h"
#include "fcntl.h"

extern "C" {

/*BOF Defs*/

DECLSPEC_IMPORT void BeaconPrintfW(int type, const wchar_t* fmt, ...);

//MSVCRT
WINBASEAPI int __cdecl MSVCRT$memcmp(const void *_Buf1,const void *_Buf2,size_t _Size);
WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);
WINBASEAPI void* __cdecl MSVCRT$memcpy(void* __restrict _Dst, const void* __restrict _Src, size_t _MaxCount);
WINBASEAPI void __cdecl MSVCRT$memset(void* dest, int c, size_t count);
WINBASEAPI int __cdecl MSVCRT$strcmp(const char* _Str1, const char* _Str2);
WINBASEAPI int __cdecl MSVCRT$_snprintf(char* s, size_t n, const char* fmt, ...);
WINBASEAPI errno_t __cdecl MSVCRT$mbstowcs_s(size_t* pReturnValue, wchar_t* wcstr, size_t sizeInWords, const char* mbstr, size_t count);
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *_Str);
WINBASEAPI char* WINAPI MSVCRT$_strlwr(char * str);
WINBASEAPI char* WINAPI MSVCRT$strrchr(char * str);
WINBASEAPI int __cdecl MSVCRT$_open_osfhandle(intptr_t osfhandle, int flags);
WINBASEAPI int __cdecl MSVCRT$_dup2( int fd1, int fd2 );
WINBASEAPI int __cdecl MSVCRT$_close(int fd);
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *_Str);
WINBASEAPI int MSVCRT$_vsnwprintf_s(wchar_t *dest, size_t destsz, size_t count, const wchar_t *format, va_list argptr); // https://www.educative.io/answers/what-is-vsnwprintfs-in-c
//KERNEL32
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess(VOID);
WINBOOL WINAPI KERNEL32$GetModuleInformation(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb);
WINBASEAPI WINBOOL WINAPI KERNEL32$FreeConsole(VOID);
WINBASEAPI DWORD WINAPI KERNEL32$QueueUserAPC (PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData);
WINBASEAPI WINBOOL WINAPI KERNEL32$ReadConsoleA(HANDLE hConsoleInput,LPVOID lpBuffer,DWORD nNumberOfCharsToRead,LPDWORD lpNumberOfCharsRead,LPVOID lpReserved);
typedef VOID* HPCON;
WINBASEAPI HRESULT WINAPI KERNEL32$CreatePseudoConsole(COORD size, HANDLE hInput, HANDLE hOutput, DWORD dwFlags, HPCON* phPC);
WINBASEAPI VOID WINAPI KERNEL32$ClosePseudoConsole(HPCON hPC);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateConsoleScreenBuffer(DWORD dwDesiredAccess,DWORD dwShareMode,CONST SECURITY_ATTRIBUTES *lpSecurityAttributes,DWORD dwFlags,LPVOID lpScreenBufferData);
WINBASEAPI WINBOOL WINAPI KERNEL32$SetConsoleActiveScreenBuffer(HANDLE hConsoleOutput);
WINBASEAPI DWORD WINAPI KERNEL32$SleepEx(DWORD dwMilliseconds, WINBOOL bAlertable);
WINBASEAPI DWORD WINAPI KERNEL32$GetCurrentThreadId(VOID);
WINBASEAPI WINBOOL WINAPI KERNEL32$SetThreadContext(HANDLE hThread, CONST CONTEXT *lpContext);
WINBASEAPI WINBOOL WINAPI KERNEL32$GetThreadContext(HANDLE hThread, LPCONTEXT lpContext);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
WINBASEAPI PVOID WINAPI KERNEL32$AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
WINBASEAPI ULONG WINAPI KERNEL32$RemoveVectoredExceptionHandler(PVOID Handle);
WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI int WINAPI KERNEL32$WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
WINBASEAPI VOID WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
WINBASEAPI void * WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
WINBASEAPI int WINAPI KERNEL32$lstrlenA(LPCSTR lpString);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *_Str);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateMailslotA(LPCSTR lpName, DWORD nMaxMessageSize, DWORD lReadTimeout, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
WINBASEAPI BOOL WINAPI KERNEL32$GetMailslotInfo(HANDLE  hMailslot, LPDWORD lpMaxMessageSize, LPDWORD lpNextSize, LPDWORD lpMessageCount, LPDWORD lpReadTimeout);
WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);
DECLSPEC_IMPORT HGLOBAL KERNEL32$GlobalAlloc(UINT uFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT HGLOBAL KERNEL32$GlobalFree(HGLOBAL hMem);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualProtect (PVOID, DWORD, DWORD, PDWORD);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (VOID);
WINBASEAPI HWND WINAPI KERNEL32$GetConsoleWindow(void);
WINBASEAPI BOOL WINAPI KERNEL32$AllocConsole(void);
WINBASEAPI HANDLE WINAPI KERNEL32$GetStdHandle(DWORD nStdHandle);
WINBASEAPI WINBOOL WINAPI KERNEL32$SetStdHandle (DWORD nStdHandle, HANDLE hHandle);
WINBASEAPI WINBOOL WINAPI KERNEL32$CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize);
//SHELL32
WINBASEAPI LPWSTR* WINAPI SHELL32$CommandLineToArgvW(LPCWSTR lpCmdLine, int* pNumArgs);
//MSCOREE
WINBASEAPI HRESULT WINAPI MSCOREE$CLRCreateInstance(REFCLSID clsid, REFIID riid, LPVOID* ppInterface);
WINBASEAPI HRESULT WINAPI MSCOREE$LoadLibraryShim(LPCWSTR,LPCWSTR,LPVOID,HMODULE*);
//OLEAUT32
WINBASEAPI SAFEARRAY* WINAPI OLEAUT32$SafeArrayCreateVector(VARTYPE vt, LONG lLbound, ULONG   cElements);
WINBASEAPI SAFEARRAY* WINAPI OLEAUT32$SafeArrayCreate(VARTYPE vt, UINT cDims, SAFEARRAYBOUND* rgsabound);
WINBASEAPI HRESULT WINAPI OLEAUT32$SafeArrayAccessData(SAFEARRAY* psa, void HUGEP** ppvData);
WINBASEAPI HRESULT WINAPI OLEAUT32$SafeArrayUnaccessData(SAFEARRAY* psa);
WINBASEAPI HRESULT WINAPI OLEAUT32$SafeArrayPutElement(SAFEARRAY* psa, LONG* rgIndices, void* pv);
WINBASEAPI HRESULT WINAPI OLEAUT32$SafeArrayDestroy(SAFEARRAY* psa);
WINBASEAPI HRESULT WINAPI OLEAUT32$VariantClear(VARIANTARG* pvarg);
WINBASEAPI BSTR WINAPI OLEAUT32$SysAllocString(const OLECHAR* psz);
//USER32
WINUSERAPI WINBOOL WINAPI USER32$ShowWindow(HWND hWnd,int nCmdShow);
WINUSERAPI int WINAPI USER32$MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
//EXTRA


typedef struct _AppDomain                 IAppDomain;
typedef struct _Assembly                  IAssembly;
typedef struct _Type                      IType;
typedef struct _Binder                    IBinder;
typedef struct _MethodInfo                IMethodInfo;
typedef struct _iobuf                     FILE;

static GUID xIID_AppDomain = { 0x05F696DC, 0x2B29, 0x3663, {0xAD, 0x8B, 0xC4,0x38, 0x9C, 0xF2, 0xA7, 0x13} };
static GUID xCLSID_CLRMetaHost = {  0x9280188d, 0xe8e, 0x4867, {0xb3, 0xc, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde} };
static GUID xIID_ICLRMetaHost = {  0xD332DB9E, 0xB9B3, 0x4125, {0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16} };
static GUID xIID_ICLRRuntimeInfo = {  0xBD39D1D2, 0xBA2F, 0x486a, {0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91} };
static GUID xIID_ICorRuntimeHost = {  0xcb2f6722, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e} };
static GUID xCLSID_CorRuntimeHost = {  0xcb2f6723, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e} };
static GUID xCLSID_ICLRRuntimeHost = { 0x90F1A06E, 0x7712, 0x4762, {0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02} };
static GUID xIID_ICLRRuntimeHost = { 0x90F1A06C, 0x7712, 0x4762, {0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02 }};
static GUID xIID_ICLRAssemblyIdentityManager = { 0x15f0a9da, 0x3ff6, 0x4393, {0x9d, 0xa9, 0xfd, 0xfd, 0x28, 0x4e, 0x69, 0x72} };
static GUID xIID_IAssemblyName = { 0xB42B6AAC, 0x317E, 0x34D5, {0x9F, 0xA9, 0x09, 0x3B, 0xB4, 0x16, 0x0C, 0x50 } };

/*
typedef enum _BindingFlags {
	BindingFlags_Default = 0,
	BindingFlags_IgnoreCase = 1,
	BindingFlags_DeclaredOnly = 2,
	BindingFlags_Instance = 4,
	BindingFlags_Static = 8,
	BindingFlags_Public = 16,
	BindingFlags_NonPublic = 32,
	BindingFlags_InvokeMethod = 256,
	BindingFlags_CreateInstance = 512,
	BindingFlags_GetField = 1024,
	BindingFlags_SetField = 2048,
	BindingFlags_GetProperty = 4096,
	BindingFlags_SetProperty = 8192,
	BindingFlags_ExactBinding = 65536,
	BindingFlags_SuppressChangeType = 131072,
	BindingFlags_OptionalParamBinding = 262144,
	BindingFlags_IgnoreReturn = 16777216
} BindingFlags;
*/



typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
  USHORT                  Flags;
  USHORT                  Length;
  ULONG                   TimeStamp;
  UNICODE_STRING          DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  ULONG                   MaximumLength;
  ULONG                   Length;
  ULONG                   Flags;
  ULONG                   DebugFlags;
  PVOID                   ConsoleHandle;
  ULONG                   ConsoleFlags;
  HANDLE                  StdInputHandle;
  HANDLE                  StdOutputHandle;
  HANDLE                  StdErrorHandle;
  UNICODE_STRING          CurrentDirectoryPath;
  HANDLE                  CurrentDirectoryHandle;
  UNICODE_STRING          DllPath;
  UNICODE_STRING          ImagePathName;
  UNICODE_STRING          CommandLine;
  PVOID                   Environment;
  ULONG                   StartingPositionLeft;
  ULONG                   StartingPositionTop;
  ULONG                   Width;
  ULONG                   Height;
  ULONG                   CharWidth;
  ULONG                   CharHeight;
  ULONG                   ConsoleTextAttributes;
  ULONG                   WindowFlags;
  ULONG                   ShowWindowFlags;
  UNICODE_STRING          WindowTitle;
  UNICODE_STRING          DesktopName;
  UNICODE_STRING          ShellInfo;
  UNICODE_STRING          RuntimeData;
  RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef VOID (WINAPI *PPS_POST_PROCESS_INIT_ROUTINE)(VOID);

typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;

typedef struct _KSYSTEM_TIME
{
     ULONG LowPart;
     LONG High1Time;
     LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;
  
typedef struct _KUSER_SHARED_DATA {
  ULONG                         TickCountLowDeprecated;
  ULONG                         TickCountMultiplier;
  KSYSTEM_TIME                  InterruptTime;
  KSYSTEM_TIME                  SystemTime;
  KSYSTEM_TIME                  TimeZoneBias;
  USHORT                        ImageNumberLow;
  USHORT                        ImageNumberHigh;
  WCHAR                         NtSystemRoot[260];
  ULONG                         MaxStackTraceDepth;
  ULONG                         CryptoExponent;
  ULONG                         TimeZoneId;
  ULONG                         LargePageMinimum;
  ULONG                         AitSamplingValue;
  ULONG                         AppCompatFlag;
  ULONGLONG                     RNGSeedVersion;
  ULONG                         GlobalValidationRunlevel;
  LONG                          TimeZoneBiasStamp;
  ULONG                         NtBuildNumber;
  //NT_PRODUCT_TYPE               NtProductType;
  BOOLEAN                       ProductTypeIsValid;
  BOOLEAN                       Reserved0[1];
  USHORT                        NativeProcessorArchitecture;
  ULONG                         NtMajorVersion;
  ULONG                         NtMinorVersion;
  //BOOLEAN                       ProcessorFeatures[PROCESSOR_FEATURE_MAX];
  ULONG                         Reserved1;
  ULONG                         Reserved3;
  ULONG                         TimeSlip;
  //ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
  ULONG                         BootId;
  LARGE_INTEGER                 SystemExpirationDate;
  ULONG                         SuiteMask;
  BOOLEAN                       KdDebuggerEnabled;
  union {
    UCHAR MitigationPolicies;
    struct {
      UCHAR NXSupportPolicy : 2;
      UCHAR SEHValidationPolicy : 2;
      UCHAR CurDirDevicesSkippedForDlls : 2;
      UCHAR Reserved : 2;
    };
  };
  USHORT                        CyclesPerYield;
  ULONG                         ActiveConsoleId;
  ULONG                         DismountCount;
  ULONG                         ComPlusPackage;
  ULONG                         LastSystemRITEventTickCount;
  ULONG                         NumberOfPhysicalPages;
  BOOLEAN                       SafeBootMode;
  union {
    UCHAR VirtualizationFlags;
    struct {
      UCHAR ArchStartedInEl2 : 1;
      UCHAR QcSlIsSupported : 1;
    };
  };
  UCHAR                         Reserved12[2];
  union {
    ULONG SharedDataFlags;
    struct {
      ULONG DbgErrorPortPresent : 1;
      ULONG DbgElevationEnabled : 1;
      ULONG DbgVirtEnabled : 1;
      ULONG DbgInstallerDetectEnabled : 1;
      ULONG DbgLkgEnabled : 1;
      ULONG DbgDynProcessorEnabled : 1;
      ULONG DbgConsoleBrokerEnabled : 1;
      ULONG DbgSecureBootEnabled : 1;
      ULONG DbgMultiSessionSku : 1;
      ULONG DbgMultiUsersInSessionSku : 1;
      ULONG DbgStateSeparationEnabled : 1;
      ULONG SpareBits : 21;
    } DUMMYSTRUCTNAME2;
  } DUMMYUNIONNAME2;
  ULONG                         DataFlagsPad[1];
  ULONGLONG                     TestRetInstruction;
  LONGLONG                      QpcFrequency;
  ULONG                         SystemCall;
  ULONG                         Reserved2;
  ULONGLONG                     FullNumberOfPhysicalPages;
  ULONGLONG                     SystemCallPad[1];
  union {
    KSYSTEM_TIME TickCount;
    ULONG64      TickCountQuad;
    struct {
      ULONG ReservedTickCountOverlay[3];
      ULONG TickCountPad[1];
    } DUMMYSTRUCTNAME;
  } DUMMYUNIONNAME3;
  ULONG                         Cookie;
  ULONG                         CookiePad[1];
  LONGLONG                      ConsoleSessionForegroundProcessId;
  ULONGLONG                     TimeUpdateLock;
  ULONGLONG                     BaselineSystemTimeQpc;
  ULONGLONG                     BaselineInterruptTimeQpc;
  ULONGLONG                     QpcSystemTimeIncrement;
  ULONGLONG                     QpcInterruptTimeIncrement;
  UCHAR                         QpcSystemTimeIncrementShift;
  UCHAR                         QpcInterruptTimeIncrementShift;
  USHORT                        UnparkedProcessorCount;
  ULONG                         EnclaveFeatureMask[4];
  ULONG                         TelemetryCoverageRound;
  USHORT                        UserModeGlobalLogger[16];
  ULONG                         ImageFileExecutionOptions;
  ULONG                         LangGenerationCount;
  ULONGLONG                     Reserved4;
  ULONGLONG                     InterruptTimeBias;
  ULONGLONG                     QpcBias;
  ULONG                         ActiveProcessorCount;
  UCHAR                         ActiveGroupCount;
  UCHAR                         Reserved9;
  union {
    USHORT QpcData;
    struct {
      UCHAR QpcBypassEnabled;
      UCHAR QpcReserved;
    };
  };
  LARGE_INTEGER                 TimeZoneBiasEffectiveStart;
  LARGE_INTEGER                 TimeZoneBiasEffectiveEnd;
  XSTATE_CONFIGURATION          XState;
  KSYSTEM_TIME                  FeatureConfigurationChangeStamp;
  ULONG                         Spare;
  ULONG64                       UserPointerAuthMask;
  XSTATE_CONFIGURATION          XStateArm64;
  ULONG                         Reserved10[210];
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;

}
