#pragma once
#include <windows.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

class HWBreakpoint
{
public:
	// The enum values correspond to the values used by the Intel Pentium,
	// so don't change them!
	enum Condition { Write = 1, ReadWrite = 3 };

	static bool Set(void* address, int len /* 1, 2, or 4 */, Condition when);
	static bool Clear(void* address);

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
	void SetForThreads(std::unique_lock<std::mutex>& lock);
	void SetThread(DWORD tid, bool enableBP);

	static void WorkerThreadProc();

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
	std::mutex m_mutex;
	std::condition_variable m_workerSignal;
	std::atomic<bool> m_workerStop;
	
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