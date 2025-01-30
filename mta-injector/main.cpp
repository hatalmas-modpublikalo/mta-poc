#include <Windows.h>
#include <stdio.h>
#include <direct.h>

#include "Registry.h"
#include "MMAP.h"

int main()
{
	STARTUPINFOA info = { sizeof(info) };
	PROCESS_INFORMATION processInfo;

	BOOL rslt = CreateProcessA(
		"C:\\Program Files (x86)\\MTA San Andreas 1.6\\Multi Theft Auto.exe",
		NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL,
		"C:\\Program Files (x86)\\MTA San Andreas 1.6",
		&info, &processInfo);

	if (rslt)
	{
		CONTEXT ctx{ 0 }; ctx.ContextFlags = CONTEXT_ALL; 
		#pragma warning(suppress: 6387)
		rslt = GetThreadContext(processInfo.hThread, &ctx);
		if (rslt)
		{
			printf("[DBG] Saving entry point instruction...\n"); DWORD dummy = NULL;
			PVOID oldCodeMem = VirtualAllocEx(processInfo.hProcess, 0, 5, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (!oldCodeMem)
			{
				printf("\nError: Unable to allocate memory for DLL data (Error: %d)\n", GetLastError());
				Sleep(3000); ExitProcess(0);
			}
			else printf("[MEMORY] Allocated data region at address: 0x%X\n", (DWORD)oldCodeMem);
			BYTE oldCode[5] = { 0x0, 0x0, 0x0, 0x0, 0x0 };
			#pragma warning(suppress: 6387)
			rslt = ReadProcessMemory(processInfo.hProcess, (PVOID)ctx.Eax, oldCode, 5, &dummy);
			if (!rslt)
			{
				printf("\nError: Unable to read memory! Last Error Code: (%d)\n", GetLastError());
				Sleep(3000); ExitProcess(0);
			}
			rslt = WriteProcessMemory(processInfo.hProcess, oldCodeMem, oldCode, 5, &dummy);
			if (rslt)
			{
				CEasyRegistry* n_reg = new CEasyRegistry(HKEY_CURRENT_USER, "Software\\Neutrino", true);
				if (n_reg)
				{
					n_reg->WriteInteger("StoredData", (DWORD)oldCodeMem);
					n_reg->WriteInteger("SpinLock", ctx.Eax);
					n_reg->WriteInteger("Thread", processInfo.dwThreadId);
					printf("[DBG] Instruction writed to allocated memory!\n");
					PVOID spinlock_addr = (PVOID)ctx.Eax; BYTE SpinLockCode[5] = { 0xE9, 0x90, 0x90, 0x90, 0x90 };
					#pragma warning(suppress: 4477)
					#pragma warning(suppress: 6273)
					printf("[DBG] Address of OEP for spinlock: 0x%X\n", (DWORD)spinlock_addr);
					DWORD Delta = (DWORD)spinlock_addr - (DWORD)spinlock_addr - 5;
					memcpy(&SpinLockCode[1], &Delta, 4); DWORD oldProt = 0x0;
					rslt = VirtualProtectEx(processInfo.hProcess, spinlock_addr, 5, PAGE_EXECUTE_READWRITE, &oldProt);
					if (!rslt)
					{
						printf("\nError: Unable to change memory access! Last Error Code: (%d)\n", GetLastError());
						Sleep(3000); ExitProcess(0);
					}
					printf("[DBG] Writing spinlock shellcode to process...\n");
					#pragma warning(suppress: 6387)
					rslt = WriteProcessMemory(processInfo.hProcess, spinlock_addr, SpinLockCode, 5, &dummy);
					if (rslt)
					{
						printf("[SUCCESS] Spinlock shellcode successfully placed!\n");
						char homePath[256]; memset(homePath, 0, sizeof(homePath));
						#pragma warning(suppress: 6031)
						_getcwd(homePath, 256); n_reg->WriteString("HomeDir", homePath); 
						rslt = VirtualProtectEx(processInfo.hProcess, spinlock_addr, 5, oldProt, &oldProt);
						if (!rslt)
						{
							printf("\nError: Unable to change memory access! Last Error Code: (%d)\n", GetLastError());
							Sleep(3000); ExitProcess(0);
						}
						MmapDLL(processInfo.hProcess, "mta-agent.dll"); delete n_reg;
						Sleep(3000); ExitProcess(0);
					}
					else printf("[ERROR] #2 Can`t write to process :( Last Error Code: %d\n", GetLastError());
				}
			}
			else printf("[ERROR] #1 Can`t write to process :( Last Error Code: %d\n", GetLastError());
		}
		else printf("[ERROR] Can`t obtain thread context. Last Error Code: %d\n", GetLastError());
		CloseHandle(processInfo.hThread); CloseHandle(processInfo.hProcess);
	}
	else printf("[ERROR] Cannot create process :( Last Error Code: %d\n", GetLastError());
	
	getchar();
}