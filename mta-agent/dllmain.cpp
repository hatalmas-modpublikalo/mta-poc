#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <thread>

#include "Registry.h"
#include "MinHook.h"

__declspec(naked) NTSTATUS NTAPI NtCreateThreadEx(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer
)
{
	__asm {
		mov     eax, 0C2h
		call    dword ptr fs : [0xC0]
		retn    2Ch
	}
}

__declspec(naked) NTSTATUS NTAPI NtCreateThreadEx2(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer
)
{
	__asm {
		mov     eax, 0C7h
		call    dword ptr fs : [0xC0]
		retn    2Ch
	}
}

__declspec(naked) NTSTATUS NTAPI NtAllocateVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG_PTR            ZeroBits,
	IN OUT PSIZE_T          RegionSize,
	IN ULONG                AllocationType,
	IN ULONG                Protect
)
{
	__asm {
		mov     eax, 18h
		call    dword ptr fs : [0xC0]
		retn    18h
	}
}

__declspec(naked) NTSTATUS NTAPI NtWriteVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN SIZE_T               NumberOfBytesToWrite,
	OUT PSIZE_T             NumberOfBytesWritten OPTIONAL
)
{
	__asm {
		mov     eax, 3Ah
		call    dword ptr fs : [0xC0]
		retn    14h
	}
}

__declspec(naked) NTSTATUS NTAPI NtFreeVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T          RegionSize,
	IN ULONG                FreeType
)
{
	__asm {
		mov     eax, 1Eh
		call    dword ptr fs : [0xC0]
		retn    10h
	}
}

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

extern "C" NTSTATUS NTAPI RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);

bool IsWindowsVersion(int targetMajor, int targetMinor, int targetBuild) {
	RTL_OSVERSIONINFOW osInfo = {};
	osInfo.dwOSVersionInfoSize = sizeof(osInfo);

	NTSTATUS status = RtlGetVersion(&osInfo);
	if (status == STATUS_SUCCESS) {
		return (osInfo.dwMajorVersion == targetMajor &&
			osInfo.dwMinorVersion == targetMinor &&
			osInfo.dwBuildNumber == targetBuild);
	}
	return false;
}

LPVOID WINAPI _VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
	DWORD nndPreferred = 0xFFFFFFFF;
	
	if (!lpAddress && (nndPreferred == -1 || nndPreferred < 0x40))
	{
		DWORD AllocationType = flAllocationType & 0xFFFFFFC0;
		if (nndPreferred != -1)
			AllocationType |= nndPreferred + 1;
		if (NT_SUCCESS(NtAllocateVirtualMemory(hProcess, &lpAddress, 0, &dwSize, AllocationType, flProtect)))
			return lpAddress;
	}

	return nullptr;
}

BOOL WINAPI _VirtualFreeEx(HANDLE hProces, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
	if (NT_SUCCESS(NtFreeVirtualMemory(hProces, &lpAddress, &dwSize, dwFreeType)))
		return TRUE;

	return FALSE;
}

bool InjectDLL(HANDLE hProc, const std::string& DLL_Path)
{
	if (hProc == nullptr || DLL_Path.empty()) return false;
	unsigned long dll_size = DLL_Path.length() + 1;
	LPVOID MyAlloc = _VirtualAllocEx(hProc, NULL, dll_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (MyAlloc == NULL) return false;
	int IsWriteOK = NtWriteVirtualMemory(hProc, MyAlloc, (PVOID)DLL_Path.c_str(), dll_size, 0);
	if (IsWriteOK == ERROR_INVALID_HANDLE) return false;
	LPTHREAD_START_ROUTINE addrLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(LoadLibraryA("kernel32.dll"), "LoadLibraryA");
	HANDLE ThreadHandle = NULL;
	if (IsWindowsVersion(10, 0, 19045)) {
		NtCreateThreadEx(&ThreadHandle, 0x1FFFFF, NULL, hProc, addrLoadLibrary, MyAlloc, FALSE, NULL, NULL, NULL, NULL);
	}
	else if (IsWindowsVersion(10, 0, 22631)) {
		NtCreateThreadEx2(&ThreadHandle, 0x1FFFFF, NULL, hProc, addrLoadLibrary, MyAlloc, FALSE, NULL, NULL, NULL, NULL);
	}
	if (ThreadHandle == NULL) return false;
	WaitForSingleObject(ThreadHandle, INFINITE);
	CloseHandle(ThreadHandle);
	_VirtualFreeEx(hProc, MyAlloc, 0, MEM_RELEASE);
	return true;
}
void ParseAndLoad(HANDLE hProc)
{
	CEasyRegistry* reg = new CEasyRegistry(HKEY_CURRENT_USER, "Software\\Neutrino", false);
	if (reg)
	{
		std::string homePath = reg->ReadString("HomeDir");
		if (!homePath.empty())
		{
			WIN32_FIND_DATAA FindFileData{ 0 };
			HANDLE hFind = FindFirstFileExA((homePath + "\\*.dll").c_str(),
			FindExInfoStandard, &FindFileData, FindExSearchNameMatch, NULL, 0);
			if (hFind != INVALID_HANDLE_VALUE)
			{
				do
				{
					std::string full_name = homePath + "\\" + FindFileData.cFileName;
					if (full_name.find("mta-agent") == std::string::npos) InjectDLL(hProc, full_name);
				} while (FindNextFileA(hFind, &FindFileData));
				FindClose(hFind);
			}
		}
		delete reg;
	}
}
typedef BOOL (__stdcall *ptrCreateProcessW)(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, 
LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
ptrCreateProcessW callCreateProcessW = nullptr;
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOL __stdcall hookedCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
	//printf("hookedCreateProcessW\n");

	/*auto addr = (BYTE*)((DWORD)GetModuleHandleA("loader") + 0x3E076);
	DWORD oldProt;
	VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &oldProt);
	addr[2] = 0xFF;
	VirtualProtect(addr, 1, oldProt, &oldProt);*/

	dwCreationFlags = CREATE_SUSPENDED;
	BOOL hndl = callCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
		lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
		lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

	ParseAndLoad(lpProcessInformation->hProcess);
	MH_DisableHook(MH_ALL_HOOKS);

	return hndl;
}

void LoadHacks()
{
	//AllocConsole();
	//freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);

	MH_Initialize();

	auto CreateProcessW = (ptrCreateProcessW)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "CreateProcessW");
	//printf("CreateProcessW: %p\n", CreateProcessW);
	MH_CreateHook(CreateProcessW, &hookedCreateProcessW, reinterpret_cast<LPVOID*>(&callCreateProcessW));
	MH_EnableHook(CreateProcessW);

	CEasyRegistry* reg = new CEasyRegistry(HKEY_CURRENT_USER, "Software\\Neutrino", false);
	if (reg)
	{
		DWORD StoredCode = reg->ReadInteger("StoredData");
		DWORD SpinLockAddr = reg->ReadInteger("SpinLock");
		BYTE oldCode[5] = { 0x0, 0x0, 0x0, 0x0, 0x0 };
		memcpy(oldCode, (PVOID)StoredCode, 5);
		DWORD oldProt = 0x0; VirtualProtect((PVOID)SpinLockAddr, 5, PAGE_EXECUTE_READWRITE, &oldProt);
		memcpy((PVOID)SpinLockAddr, oldCode, 5);
		VirtualProtect((PVOID)SpinLockAddr, 5, oldProt, &oldProt);
		DWORD thID = reg->ReadInteger("Thread");
		HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thID);
		if (hThread)
		{
			ResumeThread(hThread);
			CloseHandle(hThread);
		}
		delete reg;
	}
}
int __stdcall DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        LoadHacks();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return 1;
}

