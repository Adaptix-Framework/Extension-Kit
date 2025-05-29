#include "bofdefs.h"
#include <windows.h>
#include "beacon.h"
#ifndef bufsize
#define bufsize 8192
#endif

char * output __attribute__((section (".data"))) = 0;  // this is just done so its we don't go into .bss which isn't handled properly
WORD currentoutsize __attribute__((section (".data"))) = 0;
HANDLE trash __attribute__((section (".data"))) = NULL; // Needed for x64 to not give relocation error

#ifdef BOF
int bofstart();
void internal_printf(const char* format, ...);
void printoutput(BOOL done);
#endif
#ifdef BOF
int bofstart()
{   
    output = (char*)MSVCRT$calloc(bufsize, 1);
    currentoutsize = 0;
    return 1;
}

void internal_printf(const char* format, ...){
    int buffersize = 0;
    int transfersize = 0;
    char * curloc = NULL;
    char* intBuffer = NULL;
    va_list args;
    va_start(args, format);
    buffersize = MSVCRT$vsnprintf(NULL, 0, format, args); // +1 because vsprintf goes to buffersize-1 , and buffersize won't return with the null
    va_end(args);
    
    if (buffersize == -1)
        return;
    
    char* transferBuffer = (char*)intAlloc(bufsize);
    intBuffer = (char*)intAlloc(buffersize);
    /*Print string to memory buffer*/
    va_start(args, format);
    MSVCRT$vsnprintf(intBuffer, buffersize, format, args); // tmpBuffer2 has a null terminated string
    va_end(args);
    if(buffersize + currentoutsize < bufsize) // If this print doesn't overflow our output buffer, just buffer it to the end
    {
        memcpy(output+currentoutsize, intBuffer, buffersize);
        currentoutsize += buffersize;
    }
    else // If this print does overflow our output buffer, lets print what we have and clear any thing else as it is likely this is a large print
    {
        curloc = intBuffer;
        while(buffersize > 0)
        {
            transfersize = bufsize - currentoutsize; // what is the max we could transfer this request
            if(buffersize < transfersize) //if I have less then that, lets just transfer what's left
            {
                transfersize = buffersize;
            }
            memcpy(output+currentoutsize, curloc, transfersize); // copy data into our transfer buffer
            currentoutsize += transfersize;
            if(currentoutsize == bufsize)
            {
            printoutput(FALSE); // sets currentoutsize to 0 and prints
            }
            memset(transferBuffer, 0, transfersize); // reset our transfer buffer
            curloc += transfersize; // increment by how much data we just wrote
            buffersize -= transfersize; // subtract how much we just wrote from how much we are writing overall
        }
    }
    intFree(intBuffer);
    intFree(transferBuffer);
}

void printoutput(BOOL done)
{

    char * msg = NULL;
    BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
    currentoutsize = 0;
    memset(output, 0, bufsize);
    if(done) {MSVCRT$free(output); output=NULL;}
}
#else
#define internal_printf printf
#define printoutput 
#define bofstart 
#endif

//release any global functions here
void bofstop()
{
#ifdef DYNAMIC_LIB_COUNT
    DWORD i;
    for(i = 0; i < loadedLibrariesCount; i++)
    {
        FreeLibrary(loadedLibraries[i].hMod);
    }
#endif
	return;
}
