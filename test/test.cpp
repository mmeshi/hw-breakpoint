#include <Windows.h>
#include <iostream>
#include "..\breakpoint.h"

// extending console output with colors
enum ConsoleColor
{
	White = 7,
	Green = 10,
	Red = 12
};
std::ostream& operator<<(std::ostream& os, ConsoleColor color)
{
	static HANDLE hConsole = ::GetStdHandle(STD_OUTPUT_HANDLE);
	::SetConsoleTextAttribute(hConsole, color);
	return os;
};

// globals
int g_val = 0;
HANDLE g_hEvent1, g_hEvent2;

void tryWrite()
{
	std::cout << White << "thread " << std::hex << ::GetCurrentThreadId() << " trying to write...";

	__try 
    	{
		g_val = 1;
		std::cout << "\tmissed writes " << Red << "[failed]" << White << "\n\n" << std::flush;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		std::cout << "\tcatch write attempt " << Green << "[ok]" << White << "\n\n" << std::flush;
	}
}


DWORD WINAPI ThreadWriteFunc()
{
    	// inform main thread to set breakpoint
	::SetEvent(g_hEvent2);

    	// wait for main thread to finish setting the BP
	::WaitForSingleObject(g_hEvent1, INFINITE);

	tryWrite();

	return 0;
}

int main()
{
	HANDLE hTrd;
	DWORD threadId;

	g_hEvent1 = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	g_hEvent2 = ::CreateEvent(NULL, TRUE, FALSE, NULL);

    	// multi-thread testing:
	std::cout << "\n\ntest 1: existing thread before the BP has setting";
	std::cout <<   "\n=================================================" << std::endl;
	hTrd = ::CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadWriteFunc, NULL, 0, &threadId);
	
    	// wait for new thread creation
    	::WaitForSingleObject(g_hEvent2, INFINITE);

    	// print out the new thread id
	std::cout << "thread " << std::hex << threadId << " has created" << std::endl;

    	// set the BP
	HWBreakpoint::Set(&g_val, sizeof(int), HWBreakpoint::Write);

    	// signal the thread to continue exection (try to write)
	::SetEvent(g_hEvent1);

    	// wait for thread completion
	::WaitForSingleObject(hTrd, INFINITE);

        // cleanup and reset events
	::CloseHandle(hTrd);
	::ResetEvent(g_hEvent1);
	::ResetEvent(g_hEvent2);

	std::cout << "\n\ntest 2: new thread after setting the BP";
	std::cout <<   "\n=======================================" << std::endl;
	hTrd = ::CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadWriteFunc, NULL, 0, &threadId);

    	// wait for new thread creation
	::WaitForSingleObject(g_hEvent2, INFINITE);

    	// print out the new thread id
	std::cout << "thread " << std::hex << threadId << " has created" << std::endl;

    	// signal the thread to continue execution
	::SetEvent(g_hEvent1);

    	// wait for thread completion
	::WaitForSingleObject(hTrd, INFINITE);
	::CloseHandle(hTrd);

    	// reset the BP
	HWBreakpoint::Clear(&g_val);

    	// wait for user input
	std::cin.ignore();
}
