#ifndef UNDERLAYCOPY_H
#define UNDERLAYCOPY_H

#include <windows.h>
#include <stdint.h>

// NTFS Constants
#define MFT_RECORD_SIZE 1024
// FILE_READ_ATTRIBUTES and FILE_FLAG_BACKUP_SEMANTICS are already defined in windows.h
#define FILE_SHARE_READ 0x00000001
#define FILE_SHARE_WRITE 0x00000002
#define FILE_SHARE_DELETE 0x00000004
#define OPEN_EXISTING 3

// NTSTATUS helper
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// NtCreateFile constants (if not defined)
#ifndef FILE_READ_DATA
#define FILE_READ_DATA 0x0001
#endif
#ifndef FILE_WRITE_DATA
#define FILE_WRITE_DATA 0x0002
#endif
#ifndef FILE_OPEN
#define FILE_OPEN 1
#endif
#ifndef FILE_OVERWRITE_IF
#define FILE_OVERWRITE_IF 5
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000040
#endif
#ifndef FILE_OPEN_FOR_BACKUP_INTENT
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000
#endif
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

// NTFS Attribute Types
#define ATTRIBUTE_END 0xFFFFFFFF
#define ATTRIBUTE_FILE_NAME 0x30
#define ATTRIBUTE_DATA 0x80

// NTFS Boot Sector offsets
#define BOOT_BYTES_PER_SECTOR 11
#define BOOT_SECTORS_PER_CLUSTER 13
#define BOOT_MFT_CLUSTER 48

// Data Run structure
typedef struct {
    ULONGLONG lcn;
    ULONGLONG length;
} DATA_RUN;

// Extent structure (for Metadata mode)
typedef struct {
    ULONGLONG lcn;
    ULONGLONG lengthClusters;
} EXTENT;

// NTFS Boot Sector structure
typedef struct {
    WORD bytesPerSector;
    BYTE sectorsPerCluster;
    DWORD clusterSize;
    ULONGLONG mftCluster;
} NTFS_BOOT;

// File Info structure
typedef struct {
    ULONGLONG fileSize;
    ULONGLONG mftRecordNumber;
    DATA_RUN* runs;
    int runCount;
    BOOL hasRuns;
    BOOL isResident;
    BYTE* residentData;
    DWORD residentDataSize;
} FILE_INFO;

// Constants
#ifndef MAX_COMPUTERNAME_LENGTH
#define MAX_COMPUTERNAME_LENGTH 15
#endif

// FSCTL_GET_RETRIEVAL_POINTERS constants
#ifndef FSCTL_GET_RETRIEVAL_POINTERS
#define FSCTL_GET_RETRIEVAL_POINTERS 0x00090073
#endif

#ifndef ERROR_MORE_DATA
#define ERROR_MORE_DATA 234
#endif

// Structures for FSCTL_GET_RETRIEVAL_POINTERS are defined in winioctl.h
// STARTING_VCN_INPUT_BUFFER and RETRIEVAL_POINTERS_BUFFER are already defined there

// Helper function declarations
BOOL NormalizePathForCreateFileW(LPCWSTR path, WCHAR* normalizedPath, int bufferSize);
BOOL NormalizePathForNtCreateFile(LPCWSTR path, WCHAR* normalizedPath, int bufferSize);
BOOL CreateOutputFileNt(LPCWSTR destPath, HANDLE* hOutput);
BOOL CopyFileByExtentsToMemory(HANDLE hVolume, EXTENT* extents, DWORD extentCount, ULONGLONG clusterSize, ULONGLONG fileSize, BYTE** outputBuffer, ULONGLONG* outputSize);

// Common I/O functions
BOOL WriteSparseToFile(HANDLE hOutput, ULONGLONG offset, ULONGLONG size, BYTE* tempBuffer);
void WriteSparseToMemory(BYTE* destBuffer, ULONGLONG offset, ULONGLONG size);
BOOL CopyChunkToFile(HANDLE hVolume, HANDLE hOutput, ULONGLONG diskOffset, ULONGLONG toCopy, ULONGLONG writeOffset, BYTE* buffer, DWORD bufferSize, ULONGLONG* bytesWritten);
BOOL CopyChunkToMemory(HANDLE hVolume, BYTE* destBuffer, ULONGLONG destOffset, ULONGLONG diskOffset, ULONGLONG toCopy, BYTE* readBuffer, DWORD bufferSize, ULONGLONG* bytesCopied);

// Function declarations
BOOL ReadNtfsBoot(HANDLE hVolume, NTFS_BOOT* boot);
BOOL GetNtfsFileInfo(LPCWSTR filePath, ULONGLONG* mftRecordNumber, ULONGLONG* fileSize);
BOOL ReadMftRecord(HANDLE hVolume, NTFS_BOOT* boot, ULONGLONG recordNumber, BYTE* record);
int ParseDataRuns(BYTE* dataRuns, int dataRunsSize, DATA_RUN** runs, NTFS_BOOT* boot);
BOOL GetFileInfoFromRecord(BYTE* record, FILE_INFO* fileInfo, NTFS_BOOT* boot);
BOOL CopyFileByMft(HANDLE hVolume, HANDLE hOutput, FILE_INFO* fileInfo, NTFS_BOOT* boot);
int GetFileExtents(HANDLE hFile, EXTENT** extents, DWORD* extentCount);
BOOL CopyFileByExtents(HANDLE hVolume, HANDLE hOutput, EXTENT* extents, DWORD extentCount, ULONGLONG clusterSize, ULONGLONG fileSize);

#endif // UNDERLAYCOPY_H

