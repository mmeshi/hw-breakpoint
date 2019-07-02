#pragma once

namespace HWBreakpoint
{
    enum class Condition 
    { 
        Write = 1, 
        ReadWrite = 3 
    };

    bool Set(void* address, Condition when);
    void Clear(void* address);
    void ClearAll();
};
