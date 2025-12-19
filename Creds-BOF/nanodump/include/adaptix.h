#pragma once

#include "beacon.h"

DECLSPEC_IMPORT void AxAddScreenshot(char* note, char* data, int len);
DECLSPEC_IMPORT void AxDownloadMemory(char* filename, char* data, int len);
DECLSPEC_IMPORT void AxAddTarget(char* computer, char* domain, char* address, int os, char* os_desk, char* tag, char* info, int alive);
