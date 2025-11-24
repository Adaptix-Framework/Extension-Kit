#include <stdint.h>
#include <tchar.h>
#include "bofdefs.h"
#define CALLBACK_ERROR       0x0d

#pragma pack(push, 1)
struct BaseBlock
{
    char signature[4];
    uint32_t primarySequence;
    uint32_t secondarySequence;
    uint64_t lastModified;
    uint32_t majorVersion;
    uint32_t minorVersion;
    uint32_t fileType;
    uint32_t fileFormat;
    uint32_t rootKeyOffset;
    uint32_t hiveSize;
    uint32_t clusteringFactor;
    char reserved[64];
};
#pragma pack(pop)

struct NkKey
{
    char *name;
    uint32_t numSubkeys;
    uint32_t subkeyListOffset;
    uint32_t numValues;
    uint32_t valueListOffset;
};

struct LfList
{
    uint32_t *subkeyOffsets;
    uint16_t count;
};

struct LiList
{
    uint32_t *subkeyOffsets;
    uint16_t count;
};

struct LhList
{
    uint32_t *subkeyOffsets;
    uint16_t count;
};

struct ValueEntry
{
    char *name;
    uint32_t dataSize;
    uint32_t dataOffset;
};

// Memory management functions - maybe move this to some separate file
LPVOID AllocateMemory(SIZE_T size);
void FreeMemory(LPVOID ptr);
LPVOID ReallocateMemory(LPVOID ptr, SIZE_T size);

// Read raw data from hive (without parsing size from first 4 bytes)
BYTE *readHiveData(FILE *file, uint32_t offset, uint32_t size, uint32_t *outSize);

// Read cell from hive. Reads 4 bytes as size and other part as data
BYTE *readCell(FILE *file, uint32_t offset, uint32_t *outSize);

// Read value list entries
uint32_t *readValueList(FILE *file, uint32_t offset, uint32_t numValues, uint32_t *outCount);

// Some parsers
struct ValueEntry parseValueEntry(const BYTE *data, uint32_t dataSize);
struct NkKey parseNkKey(const BYTE *data, uint32_t dataSize);
struct LfList parseLfList(const BYTE *data, uint32_t dataSize);
struct LiList parseLiList(const BYTE *data, uint32_t dataSize);
struct LhList parseLhList(const BYTE *data, uint32_t dataSize);

// Get subkey offsets from list
uint32_t *getSubkeyOffsets(FILE *file, uint32_t subkeyListOffset, uint32_t *outCount);

// Navigate to path in registry
struct NkKey navigateToPath(FILE *file, struct NkKey *currentKey, const char **path, uint32_t pathCount);

// Parse value list entries
struct ValueEntry *parseValueList(FILE *file, uint32_t valueListOffset, uint32_t numValues, uint32_t *outCount);

// Free memory allocated by the parser
void freeNkKey(struct NkKey *key);
void freeValueEntry(struct ValueEntry *entry);
void freeLfList(struct LfList *list);
void freeLiList(struct LiList *list);
void freeLhList(struct LhList *list);

DECLSPEC_IMPORT void   BeaconPrintf(int type, char * fmt, ...);

LPVOID AllocateMemory(SIZE_T size)
{
    return Kernel32$VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

void FreeMemory(LPVOID ptr)
{
    if (ptr)
    {
        Kernel32$VirtualFree(ptr, 0, MEM_RELEASE);
    }
}

LPVOID ReallocateMemory(LPVOID ptr, SIZE_T size)
{
    if (!ptr)
    {
        return AllocateMemory(size);
    }

    LPVOID newPtr = AllocateMemory(size);
    if (!newPtr)
    {
        return NULL;
    }

    // Get the size of the old allocation
    MEMORY_BASIC_INFORMATION mbi;
    if (Kernel32$VirtualQuery(ptr, &mbi, sizeof(mbi)))
    {
        SIZE_T oldSize = mbi.RegionSize;
        SIZE_T copySize = (oldSize < size) ? oldSize : size;
        MSVCRT$memcpy(newPtr, ptr, copySize);
    }

    FreeMemory(ptr);
    return newPtr;
}

// Helper function to read data from file
static BOOL readFileData(FILE *file, uint32_t offset, void *buffer, uint32_t size)
{
    if (MSVCRT$fseek(file, 4096 + offset, SEEK_SET) != 0)
    {
        return FALSE;
    }
    return MSVCRT$fread(buffer, 1, size, file) == size;
}

BYTE *readHiveData(FILE *file, uint32_t offset, uint32_t size, uint32_t *outSize)
{
    BYTE *data = (BYTE *)AllocateMemory(size);
    if (!data)
    {
        *outSize = 0;
        return NULL;
    }

    if (!readFileData(file, offset, data, size))
    {
        FreeMemory(data);
        *outSize = 0;
        return NULL;
    }

    *outSize = size;
    return data;
}

BYTE *readCell(FILE *file, uint32_t offset, uint32_t *outSize)
{
    int32_t cellSize;
    if (!readFileData(file, offset, &cellSize, sizeof(cellSize)))
    {
        *outSize = 0;
        return NULL;
    }

    cellSize = abs(cellSize); // The size is negative if cell is unallocated
    BYTE *data = (BYTE *)AllocateMemory(cellSize - sizeof(cellSize));
    if (!data)
    {
        *outSize = 0;
        return NULL;
    }

    if (!readFileData(file, offset + sizeof(cellSize), data, cellSize - sizeof(cellSize)))
    {
        FreeMemory(data);
        *outSize = 0;
        return NULL;
    }

    *outSize = cellSize - sizeof(cellSize);
    return data;
}

uint32_t *readValueList(FILE *file, uint32_t offset, uint32_t numValues, uint32_t *outCount)
{
    int32_t cellSize;
    if (!readFileData(file, offset, &cellSize, sizeof(cellSize)))
    {
        *outCount = 0;
        return NULL;
    }

    uint32_t *valueOffsets = (uint32_t *)AllocateMemory(numValues * sizeof(uint32_t));
    if (!valueOffsets)
    {
        *outCount = 0;
        return NULL;
    }

    if (!readFileData(file, offset + sizeof(cellSize), valueOffsets, numValues * sizeof(uint32_t)))
    {
        FreeMemory(valueOffsets);
        *outCount = 0;
        return NULL;
    }

    *outCount = numValues;
    return valueOffsets;
}

struct ValueEntry parseValueEntry(const BYTE *data, uint32_t dataSize)
{
    struct ValueEntry entry = {0};
    if (dataSize < 2 || data[0] != 'v' || data[1] != 'k')
    {
        return entry;
    }

    uint16_t nameLength = *(const uint16_t *)(data + 2);
    if (2 + nameLength > dataSize)
    {
        return entry;
    }

    entry.name = (char *)AllocateMemory(nameLength + 1);
    if (!entry.name)
    {
        return entry;
    }
    MSVCRT$memcpy(entry.name, data + 20, nameLength);
    entry.name[nameLength] = '\0';

    entry.dataSize = *(const int32_t *)(data + 4);
    entry.dataOffset = *(const int32_t *)(data + 8);

    return entry;
}

struct NkKey parseNkKey(const BYTE *data, uint32_t dataSize)
{
    struct NkKey key = {0};
    if (dataSize < 0x46 || data[0] != 'n' || data[1] != 'k')
    {
        return key;
    }

    uint16_t nameLength = *(const uint16_t *)(data + 72);
    if (72 + nameLength > dataSize)
    {
        return key;
    }

    key.name = (char *)AllocateMemory(nameLength + 1);
    if (!key.name)
    {
        return key;
    }
    MSVCRT$memcpy(key.name, data + 76, nameLength);
    key.name[nameLength] = '\0';

    key.numSubkeys = *(const uint32_t *)(data + 20);
    key.subkeyListOffset = *(const uint32_t *)(data + 28);
    key.numValues = *(const uint32_t *)(data + 36);
    key.valueListOffset = *(const uint32_t *)(data + 40);

    return key;
}

struct LfList parseLfList(const BYTE *data, uint32_t dataSize)
{
    struct LfList list = {0};
    if (dataSize < 4 || data[0] != 'l' || data[1] != 'f')
    {
        return list;
    }

    list.count = *(const uint16_t *)(data + 2);
    list.subkeyOffsets = (uint32_t *)AllocateMemory(list.count * sizeof(uint32_t));
    if (!list.subkeyOffsets)
    {
        list.count = 0;
        return list;
    }

    for (uint16_t i = 0; i < list.count; ++i)
    {
        if (dataSize < 4 + (i + 1) * 8)
        {
            FreeMemory(list.subkeyOffsets);
            list.subkeyOffsets = NULL;
            list.count = 0;
            return list;
        }
        list.subkeyOffsets[i] = *(const uint32_t *)(data + 4 + i * 8);
    }

    return list;
}

struct LiList parseLiList(const BYTE *data, uint32_t dataSize)
{
    struct LiList list = {0};
    if (dataSize < 4 || data[0] != 'l' || data[1] != 'i')
    {
        return list;
    }

    list.count = *(const uint16_t *)(data + 2);
    list.subkeyOffsets = (uint32_t *)AllocateMemory(list.count * sizeof(uint32_t));
    if (!list.subkeyOffsets)
    {
        list.count = 0;
        return list;
    }

    for (uint16_t i = 0; i < list.count; ++i)
    {
        if (dataSize < 4 + (i + 1) * 4)
        {
            FreeMemory(list.subkeyOffsets);
            list.subkeyOffsets = NULL;
            list.count = 0;
            return list;
        }
        list.subkeyOffsets[i] = *(const uint32_t *)(data + 4 + i * 4);
    }

    return list;
}

struct LhList parseLhList(const BYTE *data, uint32_t dataSize)
{
    struct LhList list = {0};
    if (dataSize < 4 || data[0] != 'l' || data[1] != 'h')
    {
        return list;
    }

    list.count = *(const uint16_t *)(data + 2);
    list.subkeyOffsets = (uint32_t *)AllocateMemory(list.count * sizeof(uint32_t));
    if (!list.subkeyOffsets)
    {
        list.count = 0;
        return list;
    }

    for (uint16_t i = 0; i < list.count; ++i)
    {
        if (dataSize < 4 + (i + 1) * 8)
        {
            FreeMemory(list.subkeyOffsets);
            list.subkeyOffsets = NULL;
            list.count = 0;
            return list;
        }
        list.subkeyOffsets[i] = *(const uint32_t *)(data + 4 + i * 8);
    }

    return list;
}

uint32_t *getSubkeyOffsets(FILE *file, uint32_t subkeyListOffset, uint32_t *outCount)
{
    uint32_t cellSize;
    BYTE *listCell = readCell(file, subkeyListOffset, &cellSize);
    if (!listCell)
    {
        *outCount = 0;
        return NULL;
    }

    uint32_t *offsets = NULL;
    *outCount = 0;

    if (listCell[0] == 'l' && listCell[1] == 'f')
    {
        struct LfList list = parseLfList(listCell, cellSize);
        offsets = list.subkeyOffsets;
        *outCount = list.count;
    }
    else if (listCell[0] == 'l' && listCell[1] == 'i')
    {
        struct LiList list = parseLiList(listCell, cellSize);
        offsets = list.subkeyOffsets;
        *outCount = list.count;
    }
    else if (listCell[0] == 'l' && listCell[1] == 'h')
    {
        struct LhList list = parseLhList(listCell, cellSize);
        offsets = list.subkeyOffsets;
        *outCount = list.count;
    }
    else
    {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Unsupported list type\n");
    }

    FreeMemory(listCell);
    return offsets;
}

struct NkKey navigateToPath(FILE *file, struct NkKey *currentKey, const char **path, uint32_t pathCount)
{
    struct NkKey navigatedKey = *currentKey;

    for (uint32_t i = 0; i < pathCount; i++)
    {
        uint32_t offsetCount;
        uint32_t *offsets = getSubkeyOffsets(file, navigatedKey.subkeyListOffset, &offsetCount);
        if (!offsets)
        {
            return navigatedKey;
        }

        BOOL found = FALSE;
        for (uint32_t j = 0; j < offsetCount; j++)
        {
            uint32_t cellSize;
            BYTE *cellData = readCell(file, offsets[j], &cellSize);
            if (!cellData)
                continue;

            struct NkKey subkey = parseNkKey(cellData, cellSize);
            FreeMemory(cellData);

            if (subkey.name && MSVCRT$strcmp(subkey.name, path[i]) == 0)
            {
                freeNkKey(&navigatedKey);
                navigatedKey = subkey;
                found = TRUE;
                break;
            }
            freeNkKey(&subkey);
        }

        FreeMemory(offsets);
        if (!found)
        {
            // Path component missing
            return navigatedKey;
        }
    }

    return navigatedKey;
}

struct ValueEntry *parseValueList(FILE *file, uint32_t valueListOffset, uint32_t numValues, uint32_t *outCount)
{
    uint32_t valueCount;
    uint32_t *valueOffsets = readValueList(file, valueListOffset, numValues, &valueCount);
    if (!valueOffsets || valueCount == 0)
    {
        *outCount = 0;
        return NULL;
    }

    struct ValueEntry *entries = (struct ValueEntry *)AllocateMemory(valueCount * sizeof(struct ValueEntry));
    if (!entries)
    {
        FreeMemory(valueOffsets);
        *outCount = 0;
        return NULL;
    }

    for (uint32_t i = 0; i < valueCount; i++)
    {
        uint32_t cellSize;
        BYTE *data = readCell(file, valueOffsets[i], &cellSize);
        if (!data)
        {
            entries[i] = (struct ValueEntry){0};
            continue;
        }

        entries[i] = parseValueEntry(data, cellSize);
        FreeMemory(data);
    }

    FreeMemory(valueOffsets);
    *outCount = valueCount;
    return entries;
}

void freeNkKey(struct NkKey *key)
{
    if (key && key->name)
    {
        FreeMemory(key->name);
        key->name = NULL;
    }
}

void freeValueEntry(struct ValueEntry *entry)
{
    if (entry && entry->name)
    {
        FreeMemory(entry->name);
        entry->name = NULL;
    }
}

void freeLfList(struct LfList *list)
{
    if (list && list->subkeyOffsets)
    {
        FreeMemory(list->subkeyOffsets);
        list->subkeyOffsets = NULL;
    }
}

void freeLiList(struct LiList *list)
{
    if (list && list->subkeyOffsets)
    {
        FreeMemory(list->subkeyOffsets);
        list->subkeyOffsets = NULL;
    }
}

void freeLhList(struct LhList *list)
{
    if (list && list->subkeyOffsets)
    {
        FreeMemory(list->subkeyOffsets);
        list->subkeyOffsets = NULL;
    }
}