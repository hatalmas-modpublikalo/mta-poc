#pragma once
#include <Windows.h>

namespace scanner
{
	LPVOID scan_module(LPVOID lpBase, LPCSTR lpSignature);
	LPVOID scan_section(LPVOID lpStart, SIZE_T Size, LPCSTR lpPattern);
	LPVOID scan_region(LPVOID lpStart, SIZE_T Size, LPCSTR szSignature);
	LPVOID get_pointer_address(LPVOID lpAddress, UINT Offset);
	UINT get_imm32(LPVOID lpAddress, UINT Offset);
}
