#include <Windows.h>

#include "utils.h"
#include "hooks.h"

std::string code_all;
std::string code_once;

DWORD WINAPI MainThread(LPVOID lpThreadParameter)
{
    AllocConsole();
    freopen_s((FILE**)stdout, _xor_("CONOUT$").c_str(), "w", stdout);

    printf(_xor_("Injected mta-poc\n").c_str());

    code_all = file::read(_xor_("C:\\mta-poc\\all.lua").str());
    if (code_all.empty())
        printf(_xor_("Warning: empty all.lua\n").c_str());

    code_once = file::read(_xor_("C:\\mta-poc\\exec.lua").str());
    if (code_once.empty())
        printf(_xor_("Warning: empty exec.lua\n").c_str());

    hooks::init();

    return 0;
}

BOOL __stdcall DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        threads::resume_all();
        CreateThread(0, 0, MainThread, 0, 0, 0);
    }
    return TRUE;
}