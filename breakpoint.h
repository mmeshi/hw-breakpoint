#pragma once
#include <windows.h>
#include <thread>

class HWBreakpoint
{
public:
	// The enum values correspond to the values used by the Intel Pentium,
	// so don't change them!
	enum Condition { Write = 1, ReadWrite = 3 };

	static bool Set(void* address, int len /* 1, 2, or 4 */, Condition when);
	static bool Clear(void* address);
	static void ToggleThread(DWORD tid, bool enableBP);

private:

	static HWBreakpoint& GetInstance()
	{
		static HWBreakpoint instance;
		return instance;
	}

	HWBreakpoint();
	~HWBreakpoint();

	void BuildTrampoline();
	void ToggleThreadHook(bool set);
	static void ThreadDeutor();
	void SetForThreads();
	void SetThread(DWORD tid, bool enableBP);

	void WorkerThreadProc();

	inline void SetBits(ULONG_PTR& dw, int lowBit, int bits, int newValue)
	{
		int mask = (1 << bits) - 1; // e.g. 1 becomes 0001, 2 becomes 0011, 3 becomes 0111

		dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
	}

	int m_countActive;
	void* m_address[4];
	int m_len[4];
	Condition m_when[4];
	
	std::thread m_workerThread;
	HANDLE m_workerSignal;
	HANDLE m_workerDone;
	
	struct PendingThread
	{
		DWORD tid;
		bool enable;
	};
	volatile PendingThread m_pendingThread;

	// hook trampoline
	unsigned char* m_trampoline;
	unsigned char m_orgOpcode[8];
};