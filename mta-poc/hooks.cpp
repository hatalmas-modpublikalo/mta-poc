#pragma once

#include "hooks.h"
#include "MinHook.h"
#include "xor.h"
#include "sigscan.h"
#include "utils.h"

#include <vector>

int __fastcall hooks::AcPulsator(void* _this, void*, char a2)
{
    return 1;
}

tAcLogger pAcLogger = nullptr;
void __fastcall hooks::AcLogger(void* _this, void*, int ID, std::string* text, int size, int unk1, int unk2)
{
    bool skip{};

    switch (ID)
    {
    case 9734: // Unknown Data: V V |:808449  v:1 | Size: 0 | unk1: 0x0 | unk2: 0x177F9B8
    case 9736: // Hacks Detection Report
    case 8250: // Kick/Ban Info Report
    case 8648: // FairPlayKD communication
    case 8631: // IDK, MAYBE NOT NEEDED
    case 7060: // CPU/Motherboard/Bios/MAC/GUIDS Validation
    case 7744: // GPU Info Validation
    case 7745: // Unknown Text Data: +++++++++++++++++++
        skip = true;
        break;
    }

    if (!skip)
        pAcLogger(_this, ID, text, size, unk1, unk2);
}

tSendPacket pSendPacket = nullptr;
bool __fastcall hooks::SendPacket(void* _this, void*, unsigned char ucPacketID, void* bitStream, int packetPriority, int packetReliability, int packetOrdering)
{
    if (ucPacketID == 91 || ucPacketID == 94 || ucPacketID == 93 || ucPacketID == 25 || ucPacketID == 34)
    {
        //Log(_xor_("%s BLOCKED PACKET ID: %u\n").c_str(), buffer, ucPacketID);
        return true;
    }
    else
    {
        //Log(_xor_("%s REPORT PACKET ID: %u\n").c_str(), buffer, ucPacketID);
        return pSendPacket(_this, ucPacketID, bitStream, packetPriority, packetReliability, packetOrdering);
    }
}

tDeobfuscateScript pDeobfuscateScript = nullptr;
bool __fastcall hooks::DeobfuscateScript(void* _this, void*, const char* cpInBuffer, uint32_t uiInSize, const char** pcpOutBuffer, uint32_t* puiOutSize, const char* szScriptName)
{
    auto result = pDeobfuscateScript(_this, cpInBuffer, uiInSize, pcpOutBuffer, puiOutSize, szScriptName);

    std::string file = _xor_("C:\\mta-poc\\dump\\scripts\\").str() + szScriptName;
    file::write(file, cpInBuffer, uiInSize);

    return result;
}

extern std::string code_all;
extern std::string code_once;

bool execute_once = true;

t_luaL_loadbuffer p_luaL_loadbuffer = nullptr;
int __cdecl hooks::luaL_loadbuffer(void* L, const char* buff, size_t sz, const char* name)
{
    if (!name)
    {
        if (sz == 13261)
        {
            std::string str(buff, sz);
            str += code_all;

            if (execute_once)
            {
                str += code_once;
                execute_once = false;
            }

            return p_luaL_loadbuffer(L, str.c_str(), str.size(), name);
        }
    }

    return p_luaL_loadbuffer(L, buff, sz, name);
}

tGetSerial pGetSerial = nullptr;
void __fastcall hooks::GetSerial(void* _this, void*, char* szSerial, size_t maxLength)
{
    if (maxLength == 1)
    {
        CheckStruct* cs = (CheckStruct*)szSerial;

        //printf("cs: %p %d\n", cs->ls.s, cs->ls.size);

        cs->valid = 1;
        return;
    }

    pGetSerial(_this, szSerial, maxLength);
}

void InstallNetcHooks(HANDLE hNetc)
{
    printf(_xor_("Installing netc.dll hooks\n").c_str());

    auto Bypass = scanner::scan_module(hNetc, _xor_("80 3D ? ? ? ? 00 75 ? 80 3D ? ? ? ? 00 74 ? 80 3D ? ? ? ? 00 74").c_str());
    if (Bypass)
    {
        BYTE* byte1 = (BYTE*)scanner::get_pointer_address(Bypass, 11);
        BYTE* byte2 = (BYTE*)scanner::get_pointer_address(Bypass, 20);

        *byte1 = 1;
        *byte2 = 0;
    }
    else
        printf(_xor_("Warning: netc bypass bytes could not be found\n").c_str());

    auto AcPulsator = scanner::scan_module(hNetc, _xor_("53 8B DC 83 EC ? 83 E4 ? 83 C4 ? 55 8B 6B 04 89 6C 24 04 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 51 53 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 DC 56 57 50 8D 45 F4 64 A3 ? ? ? ? 89 65 F0 8B F9 89 BD B4 FE FF FF").c_str());
    printf(_xor_("AcPulsator: %p\n").c_str(), AcPulsator);

    if (AcPulsator)
    {
        MH_CreateHook(AcPulsator, hooks::AcPulsator, nullptr);
        MH_EnableHook(AcPulsator);
    }

    auto AcLogger = scanner::scan_module(hNetc, _xor_("55 8B EC 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC DC 00 00 00 A1 ? ? ? ? 33 C5 89 45 F0 53").c_str());
    printf_s(_xor_("AcLogger: %p\n").c_str(), AcLogger);

    if (AcLogger)
    {
        MH_CreateHook(AcLogger, hooks::AcLogger, (LPVOID*)&pAcLogger);
        MH_EnableHook(AcLogger);
    }

    auto SendPacket = scanner::scan_module(hNetc, _xor_("53 8B DC 83 EC ? 83 E4 ? 83 C4 ? 55 8B 6B 04 89 6C 24 04 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 53 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 EC 56 57 50 8D 45 F4 64 A3 ? ? ? ? 8B F1 89 B5 EC F8 FF FF").c_str());
    printf(_xor_("SendPacket: %p\n").c_str(), SendPacket);

    if (SendPacket)
    {
        MH_CreateHook(SendPacket, hooks::SendPacket, (LPVOID*)&pSendPacket);
        MH_EnableHook(SendPacket);
    }

    LPVOID* VMT = (LPVOID*)scanner::get_pointer_address(scanner::scan_module(hNetc, _xor_("C7 07 ? ? ? ? 0F 11 47 ? C7 47 ? ? ? ? ? C7 47 ? ? ? ? ? C6 47 ? ? 0F 11 47").c_str()), 2);
    LPVOID* GetSerial = VMT + 17;

    printf(_xor_("GetSerial: %p\n").c_str(), GetSerial);

    if (GetSerial)
    {
        DWORD dwOldProtect;
        pGetSerial = (tGetSerial)*GetSerial;
        VirtualProtect(GetSerial, sizeof(LPVOID), PAGE_EXECUTE_READWRITE, &dwOldProtect);
        *GetSerial = hooks::GetSerial;
        VirtualProtect(GetSerial, sizeof(LPVOID), dwOldProtect, &dwOldProtect);
    }

    /*auto DeobfuscateScript = scanner::scan_module(hNetc, _xor_("55 8b ec ff 75 18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 e8 ? ? ? ? 83 c4 14 5d c2 14 00").c_str());
    printf(_xor_("DeobfuscateScript: %p\n").c_str(), DeobfuscateScript);

    if (DeobfuscateScript)
    {
        MH_CreateHook(DeobfuscateScript, hooks::DeobfuscateScript, (LPVOID*)&pDeobfuscateScript);
        MH_EnableHook(DeobfuscateScript);
    }*/
}

std::vector<LPVOID> client_hooks;

void InstallClientHooks(HANDLE hClient)
{
    printf(_xor_("Installing client.dll hooks\n").c_str());

    LPVOID luaL_loadbuffer = scanner::scan_module(hClient, _xor_("55 8B EC 83 EC ? 8B 45 0C FF 75 14").c_str());

    printf(_xor_("luaL_loadbuffer: %p\n").c_str(), luaL_loadbuffer);

    if (luaL_loadbuffer)
    {
        MH_CreateHook(luaL_loadbuffer, hooks::luaL_loadbuffer, (LPVOID*)&p_luaL_loadbuffer);
        MH_EnableHook(luaL_loadbuffer);

        client_hooks.push_back(luaL_loadbuffer);
        execute_once = true;
    }
}

void RemoveClientHooks(HANDLE hClient)
{
    for (auto hook : client_hooks)
        MH_RemoveHook(hook);

    client_hooks.clear();
}

tLdrLoadDll pLdrLoadDll = nullptr;
NTSTATUS NTAPI hooks::LdrLoadDll(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle)
{
    auto result = pLdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle);

    if (wcsstr(ModuleFileName->Buffer, _xor_(L"netc.dll").c_str()))
    {
        printf(_xor_("netc.dll loaded\n").c_str());

        InstallNetcHooks(*ModuleHandle);
    }

    static bool active{};

    if (wcsstr(ModuleFileName->Buffer, _xor_(L"client.dll").c_str()))
    {
        wprintf(_xor_(L"client.dll loaded: %s\n").c_str(), ModuleFileName->Buffer);

        if (active)
        {
            RemoveClientHooks(*ModuleHandle);
            InstallClientHooks(*ModuleHandle);
        }

        active = true;
    }

    return result;
}

void hooks::init()
{
    HMODULE hNtdll = GetModuleHandleA(_xor_("ntdll.dll").c_str());
    if (!hNtdll)
    {
        printf(_xor_("Failed to get ntdll.dll\n").c_str());
        return;
    }

    FARPROC LdrLoadDll = GetProcAddress(hNtdll, _xor_("LdrLoadDll").c_str());

    MH_Initialize();

    MH_CreateHook(LdrLoadDll, hooks::LdrLoadDll, (LPVOID*)&pLdrLoadDll);
    MH_EnableHook(LdrLoadDll);
}
