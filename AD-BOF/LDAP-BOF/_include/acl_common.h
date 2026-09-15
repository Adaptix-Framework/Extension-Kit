#ifndef ACL_COMMON_H
#define ACL_COMMON_H

#include <windows.h>
#include <aclapi.h>

// ============================================================================
// SECURITY DESCRIPTOR STRUCTURES
// ============================================================================

// Security Descriptor Control flags
/*
#define SE_OWNER_DEFAULTED              0x0001
#define SE_GROUP_DEFAULTED              0x0002
#define SE_DACL_PRESENT                 0x0004
#define SE_DACL_DEFAULTED               0x0008
#define SE_SACL_PRESENT                 0x0010
#define SE_SACL_DEFAULTED               0x0020
#define SE_DACL_AUTO_INHERIT_REQ        0x0100
#define SE_SACL_AUTO_INHERIT_REQ        0x0200
#define SE_DACL_AUTO_INHERITED          0x0400
#define SE_SACL_AUTO_INHERITED          0x0800
#define SE_DACL_PROTECTED               0x1000
#define SE_SACL_PROTECTED               0x2000
#define SE_RM_CONTROL_VALID             0x4000
#define SE_SELF_RELATIVE                0x8000
*/

// ACL Revision constants
#ifndef ACL_REVISION
#define ACL_REVISION                    0x02
#endif
#ifndef ACL_REVISION_DS
#define ACL_REVISION_DS                 0x04
#endif

/*
// ACE Types
#define ACCESS_ALLOWED_ACE_TYPE                 0x00
#define ACCESS_DENIED_ACE_TYPE                  0x01
#define SYSTEM_AUDIT_ACE_TYPE                   0x02
#define SYSTEM_ALARM_ACE_TYPE                   0x03
#define ACCESS_ALLOWED_COMPOUND_ACE_TYPE        0x04
#define ACCESS_ALLOWED_OBJECT_ACE_TYPE          0x05
#define ACCESS_DENIED_OBJECT_ACE_TYPE           0x06
#define SYSTEM_AUDIT_OBJECT_ACE_TYPE            0x07
#define SYSTEM_ALARM_OBJECT_ACE_TYPE            0x08
#define ACCESS_ALLOWED_CALLBACK_ACE_TYPE        0x09
#define ACCESS_DENIED_CALLBACK_ACE_TYPE         0x0A
#define ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE 0x0B
#define ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  0x0C
#define SYSTEM_AUDIT_CALLBACK_ACE_TYPE          0x0D
#define SYSTEM_ALARM_CALLBACK_ACE_TYPE          0x0E
#define SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE   0x0F
#define SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE   0x10
#define SYSTEM_MANDATORY_LABEL_ACE_TYPE         0x11
#define SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE      0x12
#define SYSTEM_SCOPED_POLICY_ID_ACE_TYPE        0x13
*/

/*
// ACE Flags (Inheritance and Propagation)
#define OBJECT_INHERIT_ACE                0x01
#define CONTAINER_INHERIT_ACE             0x02
#define NO_PROPAGATE_INHERIT_ACE          0x04
#define INHERIT_ONLY_ACE                  0x08
#define INHERITED_ACE                     0x10
#define SUCCESSFUL_ACCESS_ACE_FLAG        0x40
#define FAILED_ACCESS_ACE_FLAG            0x80
*/

/*
// Access Mask - Generic Rights
#define GENERIC_READ                      0x80000000
#define GENERIC_WRITE                     0x40000000
#define GENERIC_EXECUTE                   0x20000000
#define GENERIC_ALL                       0x10000000

// Access Mask - Standard Rights
#define DELETE_ACCESS                     0x00010000
#define READ_CONTROL                      0x00020000
#define WRITE_DACL                        0x00040000
#define WRITE_OWNER                       0x00080000
#define SYNCHRONIZE                       0x00100000
#define STANDARD_RIGHTS_REQUIRED          0x000F0000
#define STANDARD_RIGHTS_READ              READ_CONTROL
#define STANDARD_RIGHTS_WRITE             READ_CONTROL
#define STANDARD_RIGHTS_EXECUTE           READ_CONTROL
#define STANDARD_RIGHTS_ALL               0x001F0000

// Access Mask - Specific Rights (DS Objects)
#define ADS_RIGHT_DS_CREATE_CHILD         0x00000001
#define ADS_RIGHT_DS_DELETE_CHILD         0x00000002
#define ADS_RIGHT_ACTRL_DS_LIST           0x00000004
#define ADS_RIGHT_DS_SELF                 0x00000008
#define ADS_RIGHT_DS_READ_PROP            0x00000010
#define ADS_RIGHT_DS_WRITE_PROP           0x00000020
#define ADS_RIGHT_DS_DELETE_TREE          0x00000040
#define ADS_RIGHT_DS_LIST_OBJECT          0x00000080
#define ADS_RIGHT_DS_CONTROL_ACCESS       0x00000100

// Object ACE Flags
#define ACE_OBJECT_TYPE_PRESENT           0x00000001
#define ACE_INHERITED_OBJECT_TYPE_PRESENT 0x00000002
*/

// Access Mask - Standard Rights
#define DELETE_ACCESS                     0x00010000
#define WRITE_DACL                        0x00040000

// Access Mask - Specific Rights (DS Objects)
#define ADS_RIGHT_DS_CREATE_CHILD         0x00000001
#define ADS_RIGHT_DS_DELETE_CHILD         0x00000002
#define ADS_RIGHT_ACTRL_DS_LIST           0x00000004
#define ADS_RIGHT_DS_SELF                 0x00000008
#define ADS_RIGHT_DS_READ_PROP            0x00000010
#define ADS_RIGHT_DS_WRITE_PROP           0x00000020
#define ADS_RIGHT_DS_DELETE_TREE          0x00000040
#define ADS_RIGHT_DS_LIST_OBJECT          0x00000080
#define ADS_RIGHT_DS_CONTROL_ACCESS       0x00000100

// ============================================================================
// WELL-KNOWN SIDS AND GUIDS
// ============================================================================

// Well-known SID strings
#define SID_EVERYONE                      "S-1-1-0"
#define SID_AUTHENTICATED_USERS           "S-1-5-11"
#define SID_SYSTEM                        "S-1-5-18"
#define SID_DOMAIN_ADMINS                 "S-1-5-21-*-512"
#define SID_ENTERPRISE_ADMINS             "S-1-5-21-*-519"

// Extended Rights GUIDs (for ADS_RIGHT_DS_CONTROL_ACCESS)
// User-Force-Change-Password
#define GUID_USER_FORCE_CHANGE_PASSWORD   "00299570-246d-11d0-a768-00aa006e0529"

// DS-Replication-Get-Changes (DCSync)
#define GUID_DS_REPLICATION_GET_CHANGES       "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
#define GUID_DS_REPLICATION_GET_CHANGES_ALL   "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
#define GUID_DS_REPLICATION_GET_CHANGES_FILTERED "89e95b76-444d-4c62-991a-0facbeda640c"

// DS-Replication-Sync (for completeness)
#define GUID_DS_REPLICATION_SYNC              "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2"

// Generic Read/Write Property GUIDs (all properties)
#define GUID_ALL_PROPERTIES                   "00000000-0000-0000-0000-000000000000"

// ============================================================================
// STRUCTURES
// ============================================================================

// ACE Header structure
#ifdef ACE_HEADER
typedef struct _ACE_HEADER {
    BYTE AceType;
    BYTE AceFlags;
    WORD AceSize;
} ACE_HEADER, *PACE_HEADER;
#endif

// Standard ACCESS_ALLOWED_ACE structure
#ifdef ACCESS_ALLOWED_ACE
typedef struct _ACCESS_ALLOWED_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD SidStart;  // First DWORD of SID
} ACCESS_ALLOWED_ACE, *PACCESS_ALLOWED_ACE;
#endif

// Object ACE structure (for extended rights)
#ifdef ACCESS_ALLOWED_OBJECT_ACE
typedef struct _ACCESS_ALLOWED_OBJECT_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    DWORD SidStart;
} ACCESS_ALLOWED_OBJECT_ACE, *PACCESS_ALLOWED_OBJECT_ACE;
#endif

// Parsed ACE information structure (for display)
typedef struct _PARSED_ACE_INFO {
    BYTE AceType;
    BYTE AceFlags;
    ACCESS_MASK Mask;
    char* TrusteeSid;          // String SID
    char* TrusteeName;         // Resolved name (optional)
    BOOL IsObjectAce;
    GUID ObjectType;           // Valid if IsObjectAce && HasObjectType
    GUID InheritedObjectType;  // Valid if IsObjectAce && HasInheritedObjectType
    BOOL HasObjectType;
    BOOL HasInheritedObjectType;
} PARSED_ACE_INFO, *PPARSED_ACE_INFO;

// Security Descriptor information structure
typedef struct _SD_INFO {
    char* OwnerSid;
    char* OwnerName;
    char* GroupSid;
    char* GroupName;
    DWORD ControlFlags;
    BOOL HasDacl;
    BOOL HasSacl;
    DWORD DaclAceCount;
    DWORD SaclAceCount;
    PARSED_ACE_INFO* DaclAces;  // Array of parsed DACL ACEs
    PARSED_ACE_INFO* SaclAces;  // Array of parsed SACL ACEs
} SD_INFO, *PSD_INFO;

// ============================================================================
// ADVAPI32 FUNCTION IMPORTS
// ============================================================================

// Security Descriptor functions
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$InitializeSecurityDescriptor(
    PSECURITY_DESCRIPTOR pSecurityDescriptor,
    DWORD dwRevision
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetSecurityDescriptorOwner(
    PSECURITY_DESCRIPTOR pSecurityDescriptor,
    PSID* pOwner,
    LPBOOL lpbOwnerDefaulted
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetSecurityDescriptorGroup(
    PSECURITY_DESCRIPTOR pSecurityDescriptor,
    PSID* pGroup,
    LPBOOL lpbGroupDefaulted
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetSecurityDescriptorDacl(
    PSECURITY_DESCRIPTOR pSecurityDescriptor,
    LPBOOL lpbDaclPresent,
    PACL* pDacl,
    LPBOOL lpbDaclDefaulted
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetSecurityDescriptorSacl(
    PSECURITY_DESCRIPTOR pSecurityDescriptor,
    LPBOOL lpbSaclPresent,
    PACL* pSacl,
    LPBOOL lpbSaclDefaulted
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetSecurityDescriptorControl(
    PSECURITY_DESCRIPTOR pSecurityDescriptor,
    PSECURITY_DESCRIPTOR_CONTROL pControl,
    LPDWORD lpdwRevision
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$SetSecurityDescriptorOwner(
    PSECURITY_DESCRIPTOR pSecurityDescriptor,
    PSID pOwner,
    BOOL bOwnerDefaulted
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$SetSecurityDescriptorGroup(
    PSECURITY_DESCRIPTOR pSecurityDescriptor,
    PSID pGroup,
    BOOL bGroupDefaulted
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$SetSecurityDescriptorDacl(
    PSECURITY_DESCRIPTOR pSecurityDescriptor,
    BOOL bDaclPresent,
    PACL pDacl,
    BOOL bDaclDefaulted
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$SetSecurityDescriptorSacl(
    PSECURITY_DESCRIPTOR pSecurityDescriptor,
    BOOL bSaclPresent,
    PACL pSacl,
    BOOL bSaclDefaulted
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$MakeAbsoluteSD(
    PSECURITY_DESCRIPTOR pSelfRelativeSecurityDescriptor,
    PSECURITY_DESCRIPTOR pAbsoluteSecurityDescriptor,
    LPDWORD lpdwAbsoluteSecurityDescriptorSize,
    PACL pDacl,
    LPDWORD lpdwDaclSize,
    PACL pSacl,
    LPDWORD lpdwSaclSize,
    PSID pOwner,
    LPDWORD lpdwOwnerSize,
    PSID pGroup,
    LPDWORD lpdwGroupSize
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$MakeSelfRelativeSD(
    PSECURITY_DESCRIPTOR pAbsoluteSecurityDescriptor,
    PSECURITY_DESCRIPTOR pSelfRelativeSecurityDescriptor,
    LPDWORD lpdwBufferLength
);

// SID functions
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSidToStringSidA(
    PSID Sid,
    LPSTR* StringSid
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertStringSidToSidA(
    LPCSTR StringSid,
    PSID* Sid
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$IsValidSid(
    PSID pSid
);

DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$GetLengthSid(
    PSID pSid
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CopySid(
    DWORD nDestinationSidLength,
    PSID pDestinationSid,
    PSID pSourceSid
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$EqualSid(
    PSID pSid1,
    PSID pSid2
);

// ACL functions
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$InitializeAcl(
    PACL pAcl,
    DWORD nAclLength,
    DWORD dwAclRevision
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetAclInformation(
    PACL pAcl,
    LPVOID pAclInformation,
    DWORD nAclInformationLength,
    ACL_INFORMATION_CLASS dwAclInformationClass
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetAce(
    PACL pAcl,
    DWORD dwAceIndex,
    LPVOID* pAce
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AddAce(
    PACL pAcl,
    DWORD dwAceRevision,
    DWORD dwStartingAceIndex,
    LPVOID pAceList,
    DWORD nAceListLength
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$DeleteAce(
    PACL pAcl,
    DWORD dwAceIndex
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AddAccessAllowedAce(
    PACL pAcl,
    DWORD dwAceRevision,
    DWORD AccessMask,
    PSID pSid
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AddAccessAllowedAceEx(
    PACL pAcl,
    DWORD dwAceRevision,
    DWORD AceFlags,
    DWORD AccessMask,
    PSID pSid
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AddAccessDeniedAce(
    PACL pAcl,
    DWORD dwAceRevision,
    DWORD AccessMask,
    PSID pSid
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AddAccessDeniedAceEx(
    PACL pAcl,
    DWORD dwAceRevision,
    DWORD AceFlags,
    DWORD AccessMask,
    PSID pSid
);

// Memory allocation for ADVAPI32 functions
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL hMem);

// GUID functions
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$UuidFromStringA(
    RPC_CSTR StringUuid,
    GUID* Uuid
);

DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$UuidToStringA(
    GUID* Uuid,
    RPC_CSTR* StringUuid
);

// ============================================================================
// SHARED FUNCTION DECLARATIONS
// ============================================================================

// Helper functions
BOOL IsDCSyncKeyword(const char* maskStr);

// Security Descriptor operations
BERVAL* ReadSecurityDescriptor(LDAP* ld, const char* objectDN);
BOOL WriteSecurityDescriptor(LDAP* ld, const char* objectDN, BERVAL* sdBerval);
PSD_INFO ParseSecurityDescriptor(BYTE* sdBuffer, DWORD sdLength);
void FreeSecurityDescriptorInfo(PSD_INFO sdInfo);

// ACE parsing and manipulation
BOOL ParseAce(PACE_HEADER aceHeader, PPARSED_ACE_INFO parsedAce);
char* GetAceTypeString(BYTE aceType);
char* GetAceFlagsString(BYTE aceFlags);
char* GetAccessMaskString(ACCESS_MASK mask);
ACCESS_MASK ParseAccessMask(const char* maskStr);
BYTE ParseAceType(const char* typeStr);
BYTE ParseAceFlags(const char* flagsStr);
char* GetInheritanceTypeString(BYTE aceFlags);

// SID utilities
char* SidToString(PSID sid);
PSID StringToSid(const char* sidString);
char* ResolveSidToName(LDAP* ld, const char* sidString, const char* defaultNC);
PSID GetSidFromAce(PACE_HEADER aceHeader);
PSID GetObjectSid(LDAP* ld, const char* objectDN);

// GUID utilities
BOOL StringToGuid(const char* guidString, GUID* guid);
char* GuidToString(GUID* guid);
char* GetGuidFriendlyName(GUID* guid);

// Display utilities
void PrintSecurityDescriptorInfo(PSD_INFO sdInfo, const char* objectDN, const char* objectSid);
void PrintFilteredSecurityDescriptorInfo(PSD_INFO sdInfo, const char* objectDN, const char* objectSid, const char* trustee);
void PrintAceInfo(PPARSED_ACE_INFO aceInfo, int index, const char* objectDN, const char* objectSid);

// ACL modification utilities
PACL CreateNewDaclWithAce(PACL oldDacl, PSID trusteeSid, ACCESS_MASK accessMask, 
                          BYTE aceType, BYTE aceFlags, GUID* objectTypeGuid, GUID* inheritedObjectTypeGuid);
PACL CreateNewDaclWithoutAces(PACL oldDacl, DWORD* aceIndicesToRemove, DWORD removeCount);
BERVAL* ConvertSecurityDescriptorToBerval(PSECURITY_DESCRIPTOR pSD);
PSECURITY_DESCRIPTOR ConvertBervalToSecurityDescriptor(BERVAL* sdBerval);

#endif // ACL_COMMON_H
