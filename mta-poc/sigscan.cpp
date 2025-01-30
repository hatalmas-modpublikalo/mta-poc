#include "sigscan.h"
#include <stdio.h>

#define INRANGE(x, a, b) (x >= a && x <= b)
#define getBits(x) (INRANGE((x & (~0x20)), 'A', 'F') ? ((x & (~0x20)) - 'A' + 0xa) : (INRANGE(x, '0', '9') ? x - '0' : 0))
#define getByte(x) (getBits((x)[0]) << 4 | getBits((x)[1]))

namespace scanner
{
	LPVOID scan_module(LPVOID lpBase, LPCSTR lpSignature)
	{
		IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)lpBase;

		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return NULL;
		}

		IMAGE_NT_HEADERS *ntHeaders = (IMAGE_NT_HEADERS *)((BYTE *)dosHeader + dosHeader->e_lfanew);

		if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			return NULL;
		}

		// check for sections
		if (ntHeaders->FileHeader.NumberOfSections == 0)
		{
			// if there are no sections try to scan the first region after the header page
			return scan_section((LPVOID)((UINT64)lpBase + 0x1000), -1, lpSignature);
		}

		IMAGE_SECTION_HEADER *sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

		for (UINT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
		{
			LPVOID lpSectionStart = (LPVOID)((UINT64)lpBase + sectionHeader[i].VirtualAddress);

			LPVOID result = scan_section(lpSectionStart, sectionHeader[i].Misc.VirtualSize, lpSignature);

			if (result)
			{
				return result;
			}
		}

		return NULL;
	}

	LPVOID scan_section(LPVOID lpStart, SIZE_T Size, LPCSTR lpPattern)
	{
		LPVOID lpEnd;
		if (Size == -1)
			lpEnd = (LPVOID)-1;
		else if (Size == 0)
			return NULL;
		else
			lpEnd = (LPVOID)((UINT64)lpStart + Size);

		LPVOID lpCurrent = lpStart;
		LPVOID res = NULL;

		// query the first page
		MEMORY_BASIC_INFORMATION mbi;

		while (VirtualQuery(lpCurrent, &mbi, sizeof(mbi)))
		{
			DWORD oldProtect = 0;

			// check if page is allocated
			if (!(mbi.State & MEM_COMMIT))
				goto next;

			// check if the page is PAGE_GUARD or PAGE_NOACCESS
			if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
			{
				// modify the page protection so we can read it
				if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect))
				{
					goto next;
				}
			}

			// scan the page
			if ((LPVOID)((UINT64)mbi.BaseAddress + mbi.RegionSize) > lpEnd)
			{
				res = scan_region(lpCurrent, (SIZE_T)((UINT64)lpEnd - (UINT64)lpCurrent), lpPattern);
			}
			else
			{
				res = scan_region(lpCurrent, mbi.RegionSize, lpPattern);
			}

			if (oldProtect)
				VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProtect, &oldProtect);

			if (res)
			{
				return res;
			}

		next:
			lpCurrent = (LPVOID)((UINT64)mbi.BaseAddress + mbi.RegionSize);

			if (lpCurrent >= lpEnd)
				break;
		}

		return NULL;
	}

	LPVOID scan_region(LPVOID lpStart, SIZE_T Size, LPCSTR szSignature)
	{
		BYTE *lpStartByte = (BYTE *)lpStart;
		BYTE *lpEndByte = (BYTE *)((UINT64)lpStart + Size);
		SIZE_T patternOffset = 0;
		SIZE_T matchCount = 0;

		if (!szSignature || !szSignature[0])
		{
			return NULL;
		}

		for (BYTE *lpCurrent = lpStartByte; lpCurrent < lpEndByte; lpCurrent++)
		{
			if (szSignature[patternOffset] == '\?' || *lpCurrent == getByte(&szSignature[patternOffset]))
			{
				matchCount++;

				if (!szSignature[patternOffset + 2])
				{
					return (LPVOID)(lpCurrent - matchCount + 1);
				}

				if (szSignature[patternOffset + 1] == '\?' || szSignature[patternOffset] != '\?')
				{
					patternOffset += 3;
				}
				else
				{
					patternOffset += 2;
				}

				if (!szSignature[patternOffset]) // if we reached the end of the signature
				{
					return (LPVOID)(lpCurrent - matchCount + 1);
				}
			}
			else if (matchCount)
			{
				lpCurrent -= (matchCount - 1);
				matchCount = 0;
				patternOffset = 0;
			}
		}

		return NULL;
	}

	LPVOID get_pointer_address(LPVOID lpAddress, UINT Offset)
	{
		if (!lpAddress)
		{
			return NULL;
		}

		return *(LPVOID*)((uintptr_t)lpAddress + Offset);
	}


	UINT get_imm32(LPVOID lpAddress, UINT Offset)
	{
		if (!lpAddress)
		{
			return 0;
		}

		return *(UINT *)((UINT64)lpAddress + Offset);
	}
}
