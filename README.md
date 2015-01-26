# hw-breakpoint
set hardware breakpoints programmaticaly - for windows x86/x64

##Features

* Works both on x86 and x64
* Multithreaded: register the breakpoint for all threads even ones that has not yet born at the moment of BP registeration

##Usage
```c++
#include "breakpoint.h"

// let's assume you have variable "val" that you want to watch on it
SomeType val;

// to set write breakpoint
HWBreakpoint::Set(&val, sizeof(SomeType), HWBreakpoint::Write);

// to set read and write breakpoint
HWBreakpoint::Set(&val, sizeof(SomeType), HWBreakpoint::ReadWrite);

// to clear the breakpoint
HWBreakpoint::Clear(&val);
```
##Credit
The accessing debug register code is based on https://github.com/mmorearty/hardware-breakpoints
