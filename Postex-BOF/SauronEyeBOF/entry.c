#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sauroneye.h"
#include "../_include/beacon.h"


static BOOL buffer_contains(const char* buf, DWORD len, const char* pat) {
    if (!buf || !pat) return FALSE;
    size_t plen = MSVCRT$strlen(pat);
    if (plen == 0 || len < (DWORD)plen) return FALSE;
    const unsigned char first = (unsigned char)pat[0];
    const DWORD max_pos = len - (DWORD)plen;
    for (DWORD i = 0; i <= max_pos; i++) {
        if ((unsigned char)buf[i] == first) {
            if (plen > 1 && (unsigned char)buf[i + plen - 1] != (unsigned char)pat[plen - 1]) {
                continue;
            }
            DWORD j = 1;
            for (; j < plen - 1; j++) {
                if ((unsigned char)buf[i + j] != (unsigned char)pat[j]) break;
            }
            if (j == plen - 1) return TRUE;
        }
    }
    return FALSE;
}
BOOL CheckForVBAMacrosStrict(const char* filepath, BOOL use_ole) {
    (void)use_ole;
    if (!filepath) return FALSE;
    HANDLE h = KERNEL32$CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    FILE_STANDARD_INFORMATION finfo = {0};
    IO_STATUS_BLOCK ios = {0};
    if (NTDLL$NtQueryInformationFile(h, &ios, &finfo, sizeof(finfo), FileStandardInformation) != 0 || finfo.EndOfFile.QuadPart == 0) {
        KERNEL32$CloseHandle(h);
        return FALSE;
    }
    ULONGLONG total = (ULONGLONG)finfo.EndOfFile.QuadPart;
    DWORD win = (DWORD)((total > OOXML_SCAN_WINDOW) ? OOXML_SCAN_WINDOW : total);
    char* buf = (char*)MSVCRT$malloc(win);
    if (!buf) { KERNEL32$CloseHandle(h); return FALSE; }
    LARGE_INTEGER off = {0};
    ios.Status = ios.Information = 0;
    BOOL isZip = FALSE, anyHit = FALSE;
    if (NTDLL$NtReadFile(h, NULL, NULL, NULL, &ios, buf, win, &off, NULL) == 0 && ios.Information >= 4) {
        isZip = (buf[0] == 'P' && buf[1] == 'K');
        anyHit = buffer_contains(buf, (DWORD)ios.Information, "vbaProject.bin");
        if (!anyHit && total > win) {
            off.QuadPart = (LONGLONG)(total - win);
            ios.Status = ios.Information = 0;
            if (NTDLL$NtReadFile(h, NULL, NULL, NULL, &ios, buf, win, &off, NULL) == 0 && ios.Information >= 4) {
                if (!isZip) isZip = (buf[0] == 'P' && buf[1] == 'K');
                anyHit = buffer_contains(buf, (DWORD)ios.Information, "vbaProject.bin");
            }
        }
    }
    MSVCRT$free(buf);
    KERNEL32$CloseHandle(h);
    return (isZip && anyHit);
}
BOOL MatchWildcard(const char* pattern, const char* str) {
    const char* s = str;
    const char* p = pattern;
    const char* star = NULL;
    const char* ss = NULL;
    while (*s) {
        if (*p == '?' || MSVCRT$tolower(*p) == MSVCRT$tolower(*s)) { s++; p++; continue; }
        if (*p == '*') { star = p++; ss = s; continue; }
        if (star) { p = star + 1; s = ++ss; continue; }
        return FALSE;
    }
    while (*p == '*') p++;
    return !*p;
}
static BOOL HasWildcard(const char* str) {
    if (!str) return FALSE;
    for (const char* p = str; *p; p++) {
        if (*p == '*' || *p == '?') return TRUE;
    }
    return FALSE;
}
static BOOL IsAlphanumeric(char c) {
    return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'));
}
static BOOL IsWordBoundary(const char* matchStart, const char* matchEnd, const char* buffer, DWORD bufferLen, const char* pattern) {
    const char* patternEnd = pattern + MSVCRT$strlen(pattern);
    const char* p = patternEnd - 1;
    BOOL endsWithStar = FALSE;
    while (p >= pattern && (*p == '*' || *p == '?')) {
        if (*p == '*') {
            endsWithStar = TRUE;
        }
        p--;
    }
    if (endsWithStar) return TRUE;
    BOOL startsWithWildcard = (*pattern == '*' || *pattern == '?');
    if (!startsWithWildcard && matchStart > buffer) {
        char prevChar = matchStart[-1];
        if (IsAlphanumeric(prevChar)) return FALSE;
    }
    if (matchEnd < buffer + bufferLen) {
        char nextChar = *matchEnd;
        if (IsAlphanumeric(nextChar)) return FALSE;
    }
    return TRUE;
}
BOOL MatchesKeyword(const char* filename, SearchOptions* opts) {
    if (opts->keyword_count == 0) return TRUE;
    const char* ext = MSVCRT$strrchr(filename, '.');
    size_t nameLen = ext ? (size_t)(ext - filename) : MSVCRT$strlen(filename);
    char* nameWithoutExt = (char*)MSVCRT$malloc(nameLen + 1);
    if (!nameWithoutExt) return FALSE;
    MSVCRT$memcpy(nameWithoutExt, filename, nameLen);
    nameWithoutExt[nameLen] = '\0';
    for (int i = 0; i < opts->keyword_count; i++) {
        const char* kw = opts->keywords[i];
        if (!kw) continue;
        if (HasWildcard(kw)) {
            if (MatchWildcard(kw, nameWithoutExt)) {
                MSVCRT$free(nameWithoutExt);
                return TRUE;
            }
        } else {
            size_t kwlen = MSVCRT$strlen(kw);
            if (nameLen == kwlen) {
                BOOL match = TRUE;
                for (size_t j = 0; j < kwlen; j++) {
                    if (MSVCRT$tolower((unsigned char)filename[j]) != MSVCRT$tolower((unsigned char)kw[j])) {
                        match = FALSE;
                        break;
                    }
                }
                if (match) {
                    MSVCRT$free(nameWithoutExt);
                    return TRUE;
                }
            }
        }
    }
    MSVCRT$free(nameWithoutExt);
    return FALSE;
}
BOOL MatchesFiletype(const char* filepath, SearchOptions* opts) {
    const char* ext = MSVCRT$strrchr(filepath, '.');
    if (!ext) return FALSE;
    for (int i = 0; i < opts->filetype_count; i++) {
        if (opts->filetypes[i] && MSVCRT$_stricmp(ext, opts->filetypes[i]) == 0) return TRUE;
    }
    return FALSE;
}
BOOL IsFolderValid(const char* path, SearchOptions* opts) {
    if (opts->system_dirs) return TRUE;
    const char* p = path;
    while (*p) {
        if (*p == ':' && (p[1] == '\\')) {
            const char* check = p + (p[2] == '\\' ? 3 : 2);
            if (MSVCRT$strncmp(check, "Windows", 7) == 0 && (check[7] == '\0' || check[7] == '\\')) return FALSE;
            if (MSVCRT$strncmp(check, "Program Files", 13) == 0) {
                check += 13;
                while (*check == '\\') check++;
                if (*check == '\0' || *check == ' ') return FALSE;
            }
            if (MSVCRT$strncmp(check, "Users", 5) == 0) {
                check += 5;
                while (*check == '\\') check++;
                if (MSVCRT$strstr(check, "AppData")) return FALSE;
            }
        }
        p++;
    }
    return TRUE;
}
static void FormatFileDate(const FILETIME* creationTime, const FILETIME* modificationTime, char* dateStr, size_t dateStrSize) {
    SYSTEMTIME st_creation, st_modification;
    KERNEL32$FileTimeToSystemTime(creationTime, &st_creation);
    KERNEL32$FileTimeToSystemTime(modificationTime, &st_modification);
    MSVCRT$_snprintf(dateStr, dateStrSize, "[C:%02d.%02d.%04d M:%02d.%02d.%04d]",
        st_creation.wDay, st_creation.wMonth, st_creation.wYear,
        st_modification.wDay, st_modification.wMonth, st_modification.wYear);
}
static BOOL OutputSearchResult(const char* filepath, const FILETIME* filetime, const char* matchStart, const char* matchEnd, const char* lowercaseBuffer, const char* originalBuffer, DWORD bufferLen, SearchOptions* opts, DWORD* seenOffsets, int* seenOffsetsCount, int seenOffsetsCapacity) {
    if (!opts) return FALSE;

    size_t len = MSVCRT$strlen(filepath);
    char* normalized = (char*)MSVCRT$malloc(len + 1);
    if (!normalized) {
        normalized = (char*)filepath; // Fallback to original path
    } else {
        MSVCRT$memcpy(normalized, filepath, len + 1);
        NormalizePath(normalized);
    }

    BOOL alreadySeen = IsPathAlreadySeen(normalized, opts);

    // Check if this match position was already output
    if (matchStart && matchEnd && seenOffsets && seenOffsetsCount) {
        size_t matchStartOffset = matchStart - lowercaseBuffer;
        size_t matchEndOffset = matchEnd - lowercaseBuffer;
        // Check if we've already output a match at this exact position or overlapping position
        for (int i = 0; i < *seenOffsetsCount; i++) {
            // Check if positions overlap (within a small tolerance to account for context differences)
            DWORD startDiff = (matchStartOffset > seenOffsets[i]) ? (matchStartOffset - seenOffsets[i]) : (seenOffsets[i] - matchStartOffset);
            if (startDiff <= CONTEXT_BUFFER_SIZE) {
                // This match overlaps with an already output match, skip it
                if (normalized != filepath) MSVCRT$free(normalized);
                return FALSE;
            }
        }
        // Add this position to seen offsets
        if (*seenOffsetsCount < seenOffsetsCapacity) {
            seenOffsets[*seenOffsetsCount] = (DWORD)matchStartOffset;
            (*seenOffsetsCount)++;
        }
    }

    char dateStr[35] = {0};
    if (opts->show_date && filetime) {
        WIN32_FILE_ATTRIBUTE_DATA fileInfo;
        FILETIME creationTime = *filetime;
        if (KERNEL32$GetFileAttributesExA(filepath, GetFileExInfoStandard, &fileInfo)) {
            creationTime = fileInfo.ftCreationTime;
        }
        FormatFileDate(&creationTime, filetime, dateStr, sizeof(dateStr));
    }

    // If file was already seen and we have a match, only output the match context
    if (alreadySeen && matchStart && matchEnd && originalBuffer) {
        size_t matchStartOffset = matchStart - lowercaseBuffer;
        size_t matchEndOffset = matchEnd - lowercaseBuffer;
        size_t contextStartOffset = (matchStartOffset < CONTEXT_BUFFER_SIZE) ? 0 : matchStartOffset - CONTEXT_BUFFER_SIZE;
        size_t contextEndOffset = (matchEndOffset + CONTEXT_BUFFER_SIZE > bufferLen) ? bufferLen : matchEndOffset + CONTEXT_BUFFER_SIZE;
        size_t ctxLen = contextEndOffset - contextStartOffset;
        char* ctx = (char*)MSVCRT$malloc(ctxLen + 1);
        if (ctx) {
            MSVCRT$memcpy(ctx, originalBuffer + contextStartOffset, ctxLen);
            ctx[ctxLen] = '\0';
            BeaconPrintf(CALLBACK_OUTPUT, "\t ...%s...\n", ctx);
            MSVCRT$free(ctx);
        }
        if (normalized != filepath) MSVCRT$free(normalized);
        return TRUE;
    }

    // If file was already seen and no match, skip
    if (alreadySeen) {
        if (normalized != filepath) MSVCRT$free(normalized);
        return FALSE;
    }

    // File not seen yet - output full result
    if (matchStart && matchEnd && originalBuffer) {
        size_t matchStartOffset = matchStart - lowercaseBuffer;
        size_t matchEndOffset = matchEnd - lowercaseBuffer;
        size_t contextStartOffset = (matchStartOffset < CONTEXT_BUFFER_SIZE) ? 0 : matchStartOffset - CONTEXT_BUFFER_SIZE;
        size_t contextEndOffset = (matchEndOffset + CONTEXT_BUFFER_SIZE > bufferLen) ? bufferLen : matchEndOffset + CONTEXT_BUFFER_SIZE;
        size_t ctxLen = contextEndOffset - contextStartOffset;
        char* ctx = (char*)MSVCRT$malloc(ctxLen + 1);
        if (ctx) {
            MSVCRT$memcpy(ctx, originalBuffer + contextStartOffset, ctxLen);
            ctx[ctxLen] = '\0';
            if (opts->show_date && dateStr[0]) {
                BeaconPrintf(CALLBACK_OUTPUT, "\n[+] %s %s:\n\t ...%s...\n", dateStr, normalized, ctx);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "\n[+] %s:\n\t ...%s...\n", normalized, ctx);
            }
            MSVCRT$free(ctx);
        } else {
            if (opts->show_date && dateStr[0]) {
                BeaconPrintf(CALLBACK_OUTPUT, "\n[+] %s %s\n", dateStr, normalized);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "\n[+] %s\n", normalized);
            }
        }
    } else {
        if (opts->show_date && dateStr[0]) {
            BeaconPrintf(CALLBACK_OUTPUT, "\n[+] %s %s\n", dateStr, normalized);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "\n[+] %s\n", normalized);
        }
    }

    AddPathToSeen(normalized, opts);
    if (normalized != filepath) MSVCRT$free(normalized);
    return TRUE;
}
BOOL MatchesDateFilter(const FILETIME* filetime, SearchOptions* opts) {
    if (!opts->has_date_filter) return TRUE;
    SYSTEMTIME st;
    KERNEL32$FileTimeToSystemTime(filetime, &st);
    int file_date = st.wYear * 10000 + st.wMonth * 100 + st.wDay;
    if (opts->before_date.wYear != 0) {
        int before = opts->before_date.wYear * 10000 + opts->before_date.wMonth * 100 + opts->before_date.wDay;
        return file_date < before;
    }
    if (opts->after_date.wYear != 0) {
        int after = opts->after_date.wYear * 10000 + opts->after_date.wMonth * 100 + opts->after_date.wDay;
        return file_date > after;
    }
    return TRUE;
}
int SearchFileContents(const char* filepath, const FILETIME* filetime, SearchOptions* opts) {
    if (!opts->search_contents || opts->keyword_count == 0) {
        return 0;
    }
    HANDLE hFile = KERNEL32$CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return 0;
    }
    DWORD fileSizeHigh = 0;
    DWORD fileSize = KERNEL32$GetFileSize(hFile, &fileSizeHigh);
    ULONGLONG totalSize = ((ULONGLONG)fileSizeHigh << 32) | fileSize;
    if (totalSize > MAX_CONTENT_BUFFER_SIZE || totalSize == 0) {
        KERNEL32$CloseHandle(hFile);
        return 0;
    }
    char* buffer = (char*)MSVCRT$malloc((size_t)totalSize + 1);
    if (!buffer) {
        KERNEL32$CloseHandle(hFile);
        return 0;
    }
    DWORD bytesRead = 0;
    if (!KERNEL32$ReadFile(hFile, buffer, (DWORD)totalSize, &bytesRead, NULL)) {
        MSVCRT$free(buffer);
        KERNEL32$CloseHandle(hFile);
        return 0;
    }
    buffer[bytesRead] = '\0';
    KERNEL32$CloseHandle(hFile);
    char* originalBuffer = (char*)MSVCRT$malloc((size_t)bytesRead + 1);
    if (!originalBuffer) {
        MSVCRT$free(buffer);
        return 0;
    }
    MSVCRT$memcpy(originalBuffer, buffer, (size_t)bytesRead + 1);
    for (DWORD i = 0; i < bytesRead; i++) {
        buffer[i] = (char)MSVCRT$tolower((unsigned char)buffer[i]);
    }
    char** lowerKeywords = (char**)MSVCRT$malloc(sizeof(char*) * opts->keyword_count);
    if (!lowerKeywords) { MSVCRT$free(buffer); MSVCRT$free(originalBuffer); return 0; }
    for (int i = 0; i < opts->keyword_count; i++) {
        const char* kw = opts->keywords[i];
        if (!kw) { lowerKeywords[i] = NULL; continue; }
        size_t len = MSVCRT$strlen(kw);
        lowerKeywords[i] = (char*)MSVCRT$malloc(len + 1);
        if (lowerKeywords[i]) {
            for (size_t j = 0; j < len; j++) lowerKeywords[i][j] = (char)MSVCRT$tolower((unsigned char)kw[j]);
            lowerKeywords[i][len] = '\0';
        } else {
            lowerKeywords[i] = NULL;
        }
    }
    // Track seen match offsets to avoid duplicate output
    DWORD* seenOffsets = (DWORD*)MSVCRT$malloc(sizeof(DWORD) * MAX_MATCHES_PER_FILE);
    int seenOffsetsCount = 0;
    int seenOffsetsCapacity = MAX_MATCHES_PER_FILE;
    if (!seenOffsets) {
        seenOffsetsCapacity = 0;
    }

    int totalMatches = 0;
    for (int i = 0; i < opts->keyword_count; i++) {
        const char* kw = opts->keywords[i];
        if (!kw || !lowerKeywords[i]) continue;
        if (HasWildcard(kw)) {
            size_t keywordLen = MSVCRT$strlen(kw);
            size_t bufferLen = bytesRead;
            char* lowerKeyword = lowerKeywords[i];
            const char* bufferEnd = buffer + bufferLen;
            const char* patternStart = lowerKeyword;
            BOOL startsWithWildcard = (*lowerKeyword == '*' || *lowerKeyword == '?');
            while (*patternStart == '*' || *patternStart == '?') {
                patternStart++;
            }
            const char* patternEnd = lowerKeyword + keywordLen - 1;
            BOOL endsWithStar = FALSE;
            while (patternEnd >= lowerKeyword && (*patternEnd == '*' || *patternEnd == '?')) {
                if (*patternEnd == '*') {
                    endsWithStar = TRUE;
                }
                patternEnd--;
            }
            if (!*patternStart) {
                const char* matchStart = buffer;
                const char* matchEnd = buffer + (bufferLen > 100 ? 100 : bufferLen);
                if (OutputSearchResult(filepath, filetime, matchStart, matchEnd, buffer, originalBuffer, (DWORD)bufferLen, opts, seenOffsets, &seenOffsetsCount, seenOffsetsCapacity)) {
                    totalMatches++;
                }
            } else {
                char firstChar = *patternStart;
                const char* searchStart = buffer;
                const char* maxSearchPos = bufferEnd;
                ULONGLONG maxSearchSize = (opts->wildcard_max_size > 0) ? opts->wildcard_max_size : WILDCARD_MAX_SEARCH_SIZE;
                if (bufferLen > maxSearchSize) {
                    maxSearchPos = buffer + (size_t)maxSearchSize;
                }
                int maxAttempts = (opts->wildcard_max_attempts > 0) ? opts->wildcard_max_attempts : WILDCARD_MAX_MATCH_ATTEMPTS;
                int attempts = 0;
                int matchCount = 0;
                while (searchStart < maxSearchPos && attempts < maxAttempts && matchCount < MAX_MATCHES_PER_FILE) {
                    while (searchStart < maxSearchPos && *searchStart != firstChar) {
                        searchStart++;
                    }
                    if (searchStart >= maxSearchPos) break;
                    size_t patternLen = MSVCRT$strlen(lowerKeyword);
                    size_t maxBackward = (patternLen < 100) ? patternLen : 100;
                    const char* tryStart = startsWithWildcard && (searchStart - buffer) > maxBackward
                        ? searchStart - maxBackward
                        : (startsWithWildcard ? buffer : searchStart);
                    BOOL foundMatch = FALSE;
                    for (const char* testStart = tryStart; testStart <= searchStart && matchCount < MAX_MATCHES_PER_FILE; testStart++) {
                        const char* p = lowerKeyword;
                        const char* t = testStart;
                        const char* lastStar = NULL;
                        const char* lastStarPos = NULL;
                        BOOL matched = TRUE;
                        int backtrackCount = 0;
                        int maxBacktrack = (opts->wildcard_max_backtrack > 0) ? opts->wildcard_max_backtrack : WILDCARD_MAX_BACKTRACK;
                        const char* firstLetterPos = NULL;
                        BOOL firstLetterFound = FALSE;
                        while (*p && t < maxSearchPos && backtrackCount < maxBacktrack) {
                            if (*p == '*') {
                                while (*p == '*') p++;
                                if (!*p) {
                                    const char* endPos = t;
                                    while (endPos < maxSearchPos && IsAlphanumeric(*endPos)) {
                                        endPos++;
                                    }
                                    const char* matchStartPos = firstLetterFound ? firstLetterPos : testStart;
                                    if (OutputSearchResult(filepath, filetime, matchStartPos, endPos, buffer, originalBuffer, (DWORD)bufferLen, opts, seenOffsets, &seenOffsetsCount, seenOffsetsCapacity)) {
                                        matchCount++;
                                        totalMatches++;
                                    }
                                    foundMatch = TRUE;
                                    matched = TRUE;
                                    break;
                                }
                                lastStar = p;
                                lastStarPos = t;
                            } else if (*p == '?' || *t == *p) {
                                if (!firstLetterFound && *p != '?') {
                                    firstLetterPos = t;
                                    firstLetterFound = TRUE;
                                }
                                p++;
                                t++;
                            } else if (lastStar) {
                                p = lastStar;
                                t = ++lastStarPos;
                                backtrackCount++;
                                firstLetterFound = FALSE;
                                firstLetterPos = NULL;
                            } else {
                                matched = FALSE;
                                break;
                            }
                        }
                        if (matched && !*p && t <= maxSearchPos) {
                            BOOL boundaryCheck = TRUE;
                            if (!endsWithStar) {
                                boundaryCheck = IsWordBoundary(testStart, t, buffer, (DWORD)bufferLen, lowerKeyword);
                            }
                            if (boundaryCheck) {
                                const char* endPos = t;
                                if (endsWithStar) {
                                    while (endPos < maxSearchPos && IsAlphanumeric(*endPos)) {
                                        endPos++;
                                    }
                                }
                                const char* matchStartPos = firstLetterFound ? firstLetterPos : testStart;
                                if (OutputSearchResult(filepath, filetime, matchStartPos, endPos, buffer, originalBuffer, (DWORD)bufferLen, opts, seenOffsets, &seenOffsetsCount, seenOffsetsCapacity)) {
                                    matchCount++;
                                    totalMatches++;
                                }
                                foundMatch = TRUE;
                            }
                        }
                    }
                    searchStart++;
                    attempts++;
                }
                if (matchCount >= MAX_MATCHES_PER_FILE) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[!] File %s: Reached maximum matches limit (%d) for pattern\n", filepath, MAX_MATCHES_PER_FILE);
                }
            }
        } else {
            size_t keywordLen = MSVCRT$strlen(kw);
            if (keywordLen == 0) continue;
            char* lowerKeyword = lowerKeywords[i];
            int matchCount = 0;
            const char* match = buffer;
            while ((match = MSVCRT$strstr(match, lowerKeyword)) != NULL && matchCount < MAX_MATCHES_PER_FILE) {
                BOOL isWordStart = (match == buffer ||
                    (match > buffer && (match[-1] < 'a' || match[-1] > 'z')));
                BOOL isWordEnd = (match + keywordLen >= buffer + bytesRead ||
                    (match[keywordLen] < 'a' || match[keywordLen] > 'z'));
                if (isWordStart && isWordEnd) {
                    const char* matchEnd = match + keywordLen;
                    if (OutputSearchResult(filepath, filetime, match, matchEnd, buffer, originalBuffer, bytesRead, opts, seenOffsets, &seenOffsetsCount, seenOffsetsCapacity)) {
                        matchCount++;
                        totalMatches++;
                    }
                    match += keywordLen;
                } else {
                    match++;
                }
            }
            if (matchCount >= MAX_MATCHES_PER_FILE) {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] File %s: Reached maximum matches limit (%d) for keyword\n", filepath, MAX_MATCHES_PER_FILE);
            }
        }
    }
    for (int i = 0; i < opts->keyword_count; i++) MSVCRT$free(lowerKeywords[i]);
    MSVCRT$free(lowerKeywords);
    MSVCRT$free(buffer);
    MSVCRT$free(originalBuffer);
    if (seenOffsets) MSVCRT$free(seenOffsets);
    return totalMatches;
}
void SearchDirectory(const char* dir_path, SearchOptions* opts) {
    WIN32_FIND_DATAA findData;
    HANDLE hFind;
    char search_path[MAX_PATH_LENGTH + 4];
    char file_path[MAX_PATH_LENGTH];
    if (opts->search_contents) {
        if (opts->result_count >= MAX_RESULTS) {
            return;
        }
    } else {
        if (opts->file_count >= MAX_RESULTS) {
            return;
        }
    }
    if (MSVCRT$strlen(dir_path) > MAX_PATH_LENGTH - 3) {
        return;
    }
    MSVCRT$_snprintf(search_path, sizeof(search_path), "%s\\*", dir_path);
    hFind = KERNEL32$FindFirstFileA(search_path, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD error = KERNEL32$GetLastError();
        if (error != ERROR_ACCESS_DENIED && error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Cannot access directory %s (Error: %lu)\n", dir_path, error);
        }
        return;
    }
    do {
        if (opts->search_contents) {
            if (opts->result_count >= MAX_RESULTS) {
                break;
            }
        } else {
            if (opts->file_count >= MAX_RESULTS) {
                break;
            }
        }
        if (MSVCRT$strcmp(findData.cFileName, ".") == 0 ||
            MSVCRT$strcmp(findData.cFileName, "..") == 0) {
            continue;
        }
        if (MSVCRT$strlen(dir_path) + MSVCRT$strlen(findData.cFileName) + 2 > MAX_PATH_LENGTH) {
            continue;
        }
        MSVCRT$_snprintf(file_path, sizeof(file_path), "%s\\%s", dir_path, findData.cFileName);
        file_path[MAX_PATH_LENGTH - 1] = '\0';
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (IsFolderValid(file_path, opts)) {
                SearchDirectory(file_path, opts);
            }
            continue;
        }
        if (!MatchesFiletype(file_path, opts)) {
            continue;
        }
        ULONGLONG file_size = ((ULONGLONG)findData.nFileSizeHigh << 32) | findData.nFileSizeLow;
        ULONGLONG file_size_kb = file_size / 1024;
        if (file_size_kb > opts->max_file_size_kb && opts->search_contents) {
            continue;
        }
        if (!MatchesDateFilter(&findData.ftLastWriteTime, opts)) {
            continue;
        }
        BOOL nameMatch = (opts->keyword_count == 0) ? TRUE : MatchesKeyword(findData.cFileName, opts);
        if (opts->check_for_macro) {
            if (!CheckForVBAMacrosStrict(file_path, FALSE)) {
                continue;
            }
        }
        int contentMatches = 0;
        if (opts->search_contents) {
            contentMatches = SearchFileContents(file_path, &findData.ftLastWriteTime, opts);
        }
        if (contentMatches > 0) {
            opts->result_count += contentMatches;
            opts->file_count++;
        } else if (nameMatch && !opts->search_contents) {
            if (IsPathAlreadySeen(file_path, opts)) {
                continue;
            }
            if (opts->file_count >= MAX_RESULTS) {
                break;
            }
            NormalizePath(file_path);
            size_t pathLen = MSVCRT$strlen(file_path);
            if (pathLen < MAX_PATH_LENGTH) {
                file_path[pathLen] = '\0';
            } else {
                file_path[MAX_PATH_LENGTH - 1] = '\0';
            }
            char dateStr[35] = {0};
            if (opts->show_date) {
                FormatFileDate(&findData.ftCreationTime, &findData.ftLastWriteTime, dateStr, sizeof(dateStr));
            }
            if (opts->show_date && dateStr[0]) {
                BeaconPrintf(CALLBACK_OUTPUT, "\n[+] %s %s\n", dateStr, file_path);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "\n[+] %s\n", file_path);
            }
            AddPathToSeen(file_path, opts);
            opts->file_count++;
        }
    } while (KERNEL32$FindNextFileA(hFind, &findData));
    KERNEL32$FindClose(hFind);
}
void TrimQuotes(char* str) {
    if (!str || !*str) return;
    char* start = str;
    while (*start == '\'' || *start == '\"') start++;
    if (!*start) { *str = '\0'; return; }
    char* end = start;
    while (*end) end++;
    while (end > start && (end[-1] == '\'' || end[-1] == '\"')) end--;
    if (start != str) {
        size_t len = end - start;
        MSVCRT$memcpy(str, start, len);
        str[len] = '\0';
    } else {
        *end = '\0';
    }
}
void NormalizePath(char* path) {
    if (!path || !*path) return;
    char* write = path;
    const char* read = path;
    while (*read) {
        if (*read == '\\' && read[1] == '\\') {
            *write++ = '\\';
            read += 2;
        } else {
            *write++ = *read++;
        }
    }
    *write = '\0';
}
void GetCanonicalPath(const char* filepath, char* canonical, size_t canonicalSize) {
    if (!filepath || !canonical || canonicalSize == 0) {
        if (canonical && canonicalSize > 0) canonical[0] = '\0';
        return;
    }
    DWORD len = KERNEL32$GetFullPathNameA(filepath, (DWORD)canonicalSize, canonical, NULL);
    if (len == 0 || len >= canonicalSize) {
        size_t pathLen = MSVCRT$strlen(filepath);
        if (pathLen >= canonicalSize) pathLen = canonicalSize - 1;
        MSVCRT$memcpy(canonical, filepath, pathLen);
        canonical[pathLen] = '\0';
    }
    NormalizePath(canonical);
    BOOL is_all_users = FALSE;
    size_t prefix_len = 0;
    if (MSVCRT$_strnicmp(canonical, "C:\\Users\\All Users", 19) == 0) {
        if (canonical[19] == '\\' || canonical[19] == '\0') {
            is_all_users = TRUE;
            prefix_len = 20;
            if (canonical[19] == '\0') prefix_len = 19;
        }
    }
    else if (MSVCRT$strncmp(canonical, "C:\\Users\\", 10) == 0) {
        const unsigned char* check = (const unsigned char*)(canonical + 10);
        const unsigned char vse_pattern[] = {0xD0, 0x92, 0xD1, 0x81, 0xD0, 0xB5, 0x20, 0xD0, 0xBF, 0xD0, 0xBE, 0xD0, 0xBB, 0xD1, 0x8C, 0xD0, 0xB7, 0xD0, 0xBE, 0xD0, 0xB2, 0xD0, 0xB0, 0xD1, 0x82, 0xD0, 0xB5, 0xD0, 0xBB, 0xD0, 0xB8};
        if (MSVCRT$memcmp(check, vse_pattern, sizeof(vse_pattern)) == 0) {
            if (canonical[10 + sizeof(vse_pattern)] == '\\' || canonical[10 + sizeof(vse_pattern)] == '\0') {
                is_all_users = TRUE;
                prefix_len = 10 + sizeof(vse_pattern) + 1;
                if (canonical[10 + sizeof(vse_pattern)] == '\0') prefix_len = 10 + sizeof(vse_pattern);
            }
        }
    }
    if (is_all_users && prefix_len > 0) {
        size_t remaining_len = MSVCRT$strlen(canonical + prefix_len);
        if (remaining_len + 16 < canonicalSize) {
            char temp[MAX_PATH_LENGTH];
            MSVCRT$memcpy(temp, "C:\\ProgramData\\", 16);
            if (remaining_len > 0) {
                MSVCRT$memcpy(temp + 15, canonical + prefix_len, remaining_len + 1);
            } else {
                temp[15] = '\0';
            }
            MSVCRT$memcpy(canonical, temp, MSVCRT$strlen(temp) + 1);
        }
    }
    for (char* p = canonical; *p; p++) {
        if ((unsigned char)*p < 128) {
            *p = (char)MSVCRT$tolower((unsigned char)*p);
        }
    }
}
BOOL IsPathAlreadySeen(const char* filepath, SearchOptions* opts) {
    if (!filepath || !opts) return FALSE;
    if (!opts->seen_paths) {
        opts->seen_paths_capacity = 256;
        opts->seen_paths = (char**)MSVCRT$malloc(sizeof(char*) * opts->seen_paths_capacity);
        if (!opts->seen_paths) return FALSE;
        opts->seen_paths_count = 0;
    }
    char canonical[MAX_PATH_LENGTH];
    GetCanonicalPath(filepath, canonical, sizeof(canonical));
    for (int i = 0; i < opts->seen_paths_count; i++) {
        if (opts->seen_paths[i] && MSVCRT$strcmp(opts->seen_paths[i], canonical) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}
void AddPathToSeen(const char* filepath, SearchOptions* opts) {
    if (!filepath || !opts) return;
    if (!opts->seen_paths) {
        opts->seen_paths_capacity = 256;
        opts->seen_paths = (char**)MSVCRT$malloc(sizeof(char*) * opts->seen_paths_capacity);
        if (!opts->seen_paths) return;
        opts->seen_paths_count = 0;
    }
    if (opts->seen_paths_count >= opts->seen_paths_capacity) {
        int new_capacity = opts->seen_paths_capacity * 2;
        char** new_array = (char**)MSVCRT$realloc(opts->seen_paths, sizeof(char*) * new_capacity);
        if (!new_array) return;
        opts->seen_paths = new_array;
        opts->seen_paths_capacity = new_capacity;
    }
    char canonical[MAX_PATH_LENGTH];
    GetCanonicalPath(filepath, canonical, sizeof(canonical));
    size_t len = MSVCRT$strlen(canonical);
    opts->seen_paths[opts->seen_paths_count] = (char*)MSVCRT$malloc(len + 1);
    if (opts->seen_paths[opts->seen_paths_count]) {
        MSVCRT$memcpy(opts->seen_paths[opts->seen_paths_count], canonical, len + 1);
        opts->seen_paths_count++;
    }
}
void ParseCSVList(char* str, char*** list, int* count) {
    if (!str || !*str) { *list = NULL; *count = 0; return; }
    int item_count = 1;
    for (int i = 0; str[i]; i++) if (str[i] == ',') item_count++;
    *list = (char**)MSVCRT$malloc(sizeof(char*) * item_count);
    *count = item_count;
    if (!*list) { *count = 0; return; }
    size_t len = MSVCRT$strlen(str);
    char* str_copy = (char*)MSVCRT$malloc(len + 1);
    if (!str_copy) { MSVCRT$free(*list); *list = NULL; *count = 0; return; }
    MSVCRT$memcpy(str_copy, str, len + 1);
    char* token = MSVCRT$strtok(str_copy, ",");
    int idx = 0;
    while (token && idx < item_count) {
        while (*token == ' ') token++;
        char* end = token + MSVCRT$strlen(token) - 1;
        while (end > token && *end == ' ') *end-- = '\0';
        TrimQuotes(token);
        NormalizePath(token);
        size_t token_len = MSVCRT$strlen(token);
        (*list)[idx] = (char*)MSVCRT$malloc(token_len + 1);
        if ((*list)[idx]) {
            MSVCRT$memcpy((*list)[idx], token, token_len + 1);
            idx++;
        }
        token = MSVCRT$strtok(NULL, ",");
    }
    *count = idx;
    MSVCRT$free(str_copy);
}
static char* AllocString(const char* src) {
    if (!src) return NULL;
    size_t len = MSVCRT$strlen(src);
    char* dst = (char*)MSVCRT$malloc(len + 1);
    if (dst) {
        MSVCRT$memcpy(dst, src, len + 1);
    }
    return dst;
}
BOOL ParseDate(const char* date_str, SYSTEMTIME* st) {
    if (MSVCRT$strlen(date_str) != 10 || date_str[2] != '.' || date_str[5] != '.') return FALSE;
    st->wDayOfWeek = st->wHour = st->wMinute = st->wSecond = st->wMilliseconds = 0;
    st->wDay = (WORD)((date_str[0] - '0') * 10 + (date_str[1] - '0'));
    st->wMonth = (WORD)((date_str[3] - '0') * 10 + (date_str[4] - '0'));
    st->wYear = (WORD)((date_str[6] - '0') * 1000 + (date_str[7] - '0') * 100 + (date_str[8] - '0') * 10 + (date_str[9] - '0'));
    return (st->wYear >= 1900 && st->wYear <= 9999 && st->wMonth >= 1 && st->wMonth <= 12 && st->wDay >= 1 && st->wDay <= 31);
}
void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    char* raw_cmdline = BeaconDataExtract(&parser, NULL);
    SearchOptions opts = {0};
    opts.max_file_size_kb = 1024;
    opts.system_dirs = FALSE;
    opts.search_contents = FALSE;
    opts.check_for_macro = FALSE;
    opts.has_date_filter = FALSE;
    opts.show_date = FALSE;
    opts.result_count = 0;
    opts.file_count = 0;
    opts.wildcard_max_attempts = 0;
    opts.wildcard_max_size = 0;
    opts.wildcard_max_backtrack = 0;
    opts.seen_paths = NULL;
    opts.seen_paths_count = 0;
    opts.seen_paths_capacity = 0;
    if (raw_cmdline && *raw_cmdline) {
        const char* p = raw_cmdline;
        while (*p) {
            if (*p == '-' && p[1]) {
                const char valid_flags[] = "-d-f-k-c-m-s-b-a-v-D-W-S-B";
                BOOL valid = FALSE;
                for (int i = 0; i < (int)sizeof(valid_flags) - 1; i += 2) {
                    if (p[0] == valid_flags[i] && p[1] == valid_flags[i+1]) { valid = TRUE; break; }
                }
                if (!valid) {
                    char flag[3] = {p[0], p[1], '\0'};
                    BeaconPrintf(CALLBACK_ERROR, "Invalid flag: %s\n", flag);
                    return;
                }
                while (*p && *p != ' ' && *p != '\t') p++;
            } else p++;
        }
    }
    char* directories_str = BeaconDataExtract(&parser, NULL);
    char* filetypes_str = BeaconDataExtract(&parser, NULL);
    char* keywords_str = BeaconDataExtract(&parser, NULL);
    int search_contents_int = BeaconDataInt(&parser);
    int max_filesize_int = BeaconDataInt(&parser);
    int system_dirs_int = BeaconDataInt(&parser);
    char* before_date_str = BeaconDataExtract(&parser, NULL);
    char* after_date_str = BeaconDataExtract(&parser, NULL);
    int check_macro_int = BeaconDataInt(&parser);
    int show_date_int = BeaconDataInt(&parser);
    int wildcard_attempts_int = BeaconDataInt(&parser);
    int wildcard_size_int = BeaconDataInt(&parser);
    int wildcard_backtrack_int = BeaconDataInt(&parser);
    opts.search_contents = (search_contents_int != 0);
    opts.system_dirs = (system_dirs_int != 0);
    opts.check_for_macro = (check_macro_int != 0);
    opts.show_date = (show_date_int != 0);
    if (max_filesize_int > 0) opts.max_file_size_kb = (ULONGLONG)max_filesize_int;
    if (wildcard_attempts_int > 0) opts.wildcard_max_attempts = wildcard_attempts_int;
    if (wildcard_size_int > 0) opts.wildcard_max_size = (ULONGLONG)wildcard_size_int * 1024;
    if (wildcard_backtrack_int > 0) opts.wildcard_max_backtrack = wildcard_backtrack_int;
    if (directories_str && MSVCRT$strlen(directories_str) > 0) {
        ParseCSVList(directories_str, &opts.directories, &opts.dir_count);
    } else {
        opts.dir_count = 1;
        opts.directories = (char**)MSVCRT$malloc(sizeof(char*) * 1);
        if (opts.directories) {
            opts.directories[0] = AllocString("C:\\");
        }
    }
    if (filetypes_str && MSVCRT$strlen(filetypes_str) > 0) {
        ParseCSVList(filetypes_str, &opts.filetypes, &opts.filetype_count);
    } else {
        if (opts.check_for_macro) {
            const char* default_types[] = {".doc", ".xls", ".docm", ".xlsm"};
            opts.filetype_count = 4;
            opts.filetypes = (char**)MSVCRT$malloc(sizeof(char*) * 4);
            if (opts.filetypes) {
                for (int i = 0; i < 4; i++) {
                    opts.filetypes[i] = AllocString(default_types[i]);
                }
            }
        } else {
            const char* default_types[] = {".txt", ".docx"};
            opts.filetype_count = 2;
            opts.filetypes = (char**)MSVCRT$malloc(sizeof(char*) * 2);
            if (opts.filetypes) {
                for (int i = 0; i < 2; i++) {
                    opts.filetypes[i] = AllocString(default_types[i]);
                }
            }
        }
    }
    if (keywords_str && MSVCRT$strlen(keywords_str) > 0) {
        ParseCSVList(keywords_str, &opts.keywords, &opts.keyword_count);
    } else {
        opts.keyword_count = 0;
        opts.keywords = NULL;
    }
    if (before_date_str && *before_date_str) {
        if (ParseDate(before_date_str, &opts.before_date)) opts.has_date_filter = TRUE;
        else BeaconPrintf(CALLBACK_ERROR, "[-] Invalid before date format: %s\n", before_date_str);
    }
    if (after_date_str && *after_date_str) {
        if (ParseDate(after_date_str, &opts.after_date)) opts.has_date_filter = TRUE;
        else BeaconPrintf(CALLBACK_ERROR, "[-] Invalid after date format: %s\n", after_date_str);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting SauronEye search...\n[*] Directories: ");
    for (int i = 0; i < opts.dir_count; i++) BeaconPrintf(CALLBACK_OUTPUT, "%s ", opts.directories[i]);
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
    for (int i = 0; i < opts.dir_count; i++) {
        if (opts.search_contents) {
            if (opts.result_count >= MAX_RESULTS) {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] Reached maximum results limit (%d)\n", MAX_RESULTS);
                break;
            }
        } else {
            if (opts.file_count >= MAX_RESULTS) {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] Reached maximum files limit (%d)\n", MAX_RESULTS);
                break;
            }
        }
        if (SHLWAPI$PathFileExistsA(opts.directories[i])) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Searching in: %s\n", opts.directories[i]);
            SearchDirectory(opts.directories[i], &opts);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] Directory does not exist: %s\n", opts.directories[i]);
        }
    }
    if (opts.search_contents && opts.result_count > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Search completed. Found %d results in %d files.\n", opts.result_count, opts.file_count);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Search completed. Found %d files.\n", opts.file_count);
    }
    if (opts.seen_paths) {
        for (int i = 0; i < opts.seen_paths_count; i++) {
            if (opts.seen_paths[i]) {
                MSVCRT$free(opts.seen_paths[i]);
            }
        }
        MSVCRT$free(opts.seen_paths);
    }
}