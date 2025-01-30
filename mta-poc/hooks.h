#pragma once

#include <Windows.h>
#include <string>

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

struct CVector
{
	float x, y, z;
};

struct LoadS
{
	const char* s;
	size_t size;
};

struct CheckStruct
{
	DWORD valid;
	DWORD main_state;
	LoadS ls;
	const char* name;
};

typedef void(__thiscall* tAcLogger)(void* _this, int ID, std::string* text, int size, int unk1, int unk2);
typedef int(__thiscall* tSendPacket)(void* _this, unsigned char ucPacketID, void* bitStream, int packetPriority, int packetReliability, int packetOrdering);
typedef bool(__thiscall* tDeobfuscateScript)(void* _this, const char* cpInBuffer, uint32_t uiInSize, const char** pcpOutBuffer, uint32_t* puiOutSize, const char* szScriptName);
typedef void(__thiscall* tGetSerial)(void* _this, char* szSerial, size_t maxLength);
typedef int(__cdecl* t_luaL_loadbuffer)(void* L, const char* buff, size_t sz, const char* name);
typedef NTSTATUS(NTAPI* tLdrLoadDll)(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);

namespace hooks
{
	void init();

	int __fastcall AcPulsator(void* _this, void*, char a2);
	void __fastcall AcLogger(void* _this, void*, int ID, std::string* text, int size, int unk1, int unk2);
	bool __fastcall SendPacket(void* _this, void*, unsigned char ucPacketID, void* bitStream, int packetPriority, int packetReliability, int packetOrdering);
	bool __fastcall DeobfuscateScript(void* _this, void*, const char* cpInBuffer, uint32_t uiInSize, const char** pcpOutBuffer, uint32_t* puiOutSize, const char* szScriptName);
	void __fastcall GetSerial(void* _this, void*, char* szSerial, size_t maxLength);
	int __cdecl CreateObject(void* Resource, unsigned short usModelID, const CVector& vecPosition, const CVector& vecRotation, bool bLowLod);
	int __cdecl luaL_loadbuffer(void* L, const char* buff, size_t sz, const char* name);
	NTSTATUS NTAPI LdrLoadDll(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);
}
