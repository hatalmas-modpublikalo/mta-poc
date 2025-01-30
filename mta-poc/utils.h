#pragma once

#include "xor.h"

namespace threads
{
    void resume_all();
}

namespace file
{
    std::string read(const std::string& fileName);
    void write(const std::string& fileName, const char* data, size_t size);
}