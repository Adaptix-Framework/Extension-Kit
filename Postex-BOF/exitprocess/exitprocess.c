#include <windows.h>
#include "bofdefs.h"
#include "beacon.h"

void go(char* buff, int len) {
    NTDLL$RtlExitUserProcess(0);
}
