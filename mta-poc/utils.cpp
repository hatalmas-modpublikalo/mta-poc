#include "utils.h"

#include <Windows.h>
#include <TlHelp32.h>
#include <fstream>
#include <filesystem>
#include <iostream>

void threads::resume_all()
{
    HANDLE Toolhelp32Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (Toolhelp32Snapshot == INVALID_HANDLE_VALUE)
        return;

    THREADENTRY32 te{ 0 };
    te.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(Toolhelp32Snapshot, &te))
    {
        do
        {
            if (te.th32OwnerProcessID == GetCurrentProcessId())
            {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, 0, te.th32ThreadID);
                if (hThread)
                {
                    ResumeThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(Toolhelp32Snapshot, &te));
    }
    CloseHandle(Toolhelp32Snapshot);
}

std::string file::read(const std::string& fileName) {
    std::ifstream file(fileName);
    if (!file) {
        return "";
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

void file::write(const std::string& fileName, const char* data, size_t size) {
    std::filesystem::path dirPath(fileName);
    dirPath.remove_filename();

    std::error_code ec;
    if (!std::filesystem::create_directories(dirPath, ec) && ec) {
        printf(_xor_("create_directories fail: %s\n").c_str(), dirPath.string().c_str());
        return;
    }

    std::ofstream file(fileName, std::ios::binary | std::ios::app);
    if (!file) {
        printf(_xor_("Failed to open file: %s\n").c_str(), fileName.c_str());
        return;
    }

    file.write(data, size);
}