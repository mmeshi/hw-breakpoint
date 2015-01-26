#include "breakpoint.h"
#include <windows.h>
#include <tlhelp32.h>
#include <algorithm>
#include <iostream>

class CriticalSection
{
public:
	CriticalSection() { InitializeCriticalSection(&m_cs); }
	~CriticalSection() { DeleteCriticalSection(&m_cs); }

	void Enter() { EnterCriticalSection(&m_cs); }
	void Leave() { LeaveCriticalSection(&m_cs); }

	class Scope
	{
	public:
		Scope(CriticalSection& cs) : _cs(cs) { _cs.Enter(); }
		~Scope() { _cs.Leave(); }
	private:
		CriticalSection& _cs;
	};

private:
	CRITICAL_SECTION m_cs;
} cs;


HWBreakpoint::HWBreakpoint()
{
	ZeroMemory(m_address, sizeof(m_address));
	m_countActive = 0;

	BuildTrampoline();
	if (!m_trampoline)
		std::cout << "[HWBreakpoint] error: failed to build hook function" << std::endl;

	m_workerSignal = CreateEvent(NULL, FALSE, FALSE, NULL);
	m_workerDone = CreateEvent(NULL, FALSE, FALSE, NULL);
	m_workerThread = CreateThread(NULL, 0, WorkerThreadProc, this, 0, NULL);
	WaitForSingleObject(m_workerDone, INFINITE);
}

HWBreakpoint::~HWBreakpoint()
{
	{
		CriticalSection::Scope lock(cs);
		ZeroMemory(m_address, sizeof(m_address));
		SetForThreads();
	}

	m_pendingThread.tid = -1;
	SetEvent(m_workerSignal);
	WaitForSingleObject(m_workerThread, INFINITE);
	CloseHandle(m_workerDone);
	CloseHandle(m_workerSignal);
	CloseHandle(m_workerThread);

	if (m_trampoline)
		VirtualFree(m_trampoline, 0, MEM_RELEASE);
}

bool HWBreakpoint::Set(void* address, int len, Condition when)
{
	HWBreakpoint& bp = GetInstance();
	{
		CriticalSection::Scope lock(cs);
		for (int index = 0; index < 4; ++index)
			if (bp.m_address[index] == nullptr)
			{
				bp.m_address[index] = address;
				bp.m_len[index] = len;
				bp.m_when[index] = when;
				if (bp.m_countActive++ == 0)
					bp.ToggleThreadHook(true);
				bp.SetForThreads();
				return true;
			}
	}

	return false;
}

bool HWBreakpoint::Clear(void* address)
{
	HWBreakpoint& bp = GetInstance();
	{
		CriticalSection::Scope lock(cs);
		for (int index = 0; index < 4; ++index)
			if (bp.m_address[index] == address)
			{
				bp.m_address[index] = nullptr;
				if (--bp.m_countActive == 0)
					bp.ToggleThreadHook(false);
				bp.SetForThreads();
				return true;
			}
	}

	return false;
}

void HWBreakpoint::ToggleThread(DWORD tid, bool enableBP)
{
	HWBreakpoint& bp = GetInstance();
	{
		CriticalSection::Scope lock(cs);
		bp.m_pendingThread.tid = tid;
		bp.m_pendingThread.enable = enableBP;
		SetEvent(bp.m_workerSignal);
		WaitForSingleObject(bp.m_workerDone, INFINITE);
	}
}

void HWBreakpoint::BuildTrampoline()
{
	ULONG_PTR* rtlThreadStartAddress = (ULONG_PTR*)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlUserThreadStart");

	SYSTEM_INFO si;
	GetSystemInfo(&si);

#ifdef _WIN64

	// Explanation: 
	// the traditional way is to overwite first instructions in the hook target with
	// an relative uncontitional jmp. this works well in x86 when a relative jmp takes
	// only 5 bytes of opcode and is capable to cover all memory space. things is differente in x64 mode, 
	// to cover all memory space, one need to use absolute jmp which cost 14 bytes in opcode. this is too
	// long to overwite for very small functions. the solution is to use two steps: the overwite instruction 
	// is a 5 byte relative jmp that jump to a trampoline function, allocated not far from 2GB relative to the
	// target hook. and in the trampoline we have space to specify absolute jump to the real hook function.
	// more details in: http://www.codeproject.com/Articles/44326/MinHook-The-Minimalistic-x-x-API-Hooking-Libra

	// search for avalible memory in 2GB boundary to host the tampoline function
	ULONG_PTR gMinAddress = (ULONG_PTR)si.lpMinimumApplicationAddress;
	ULONG_PTR gMaxAddress = (ULONG_PTR)si.lpMaximumApplicationAddress;
	ULONG_PTR minAddr = std::max<ULONG_PTR>(gMinAddress, (ULONG_PTR)rtlThreadStartAddress - 0x20000000);
	ULONG_PTR maxAddr = std::min<ULONG_PTR>(gMaxAddress, (ULONG_PTR)rtlThreadStartAddress + 0x20000000);

	const size_t BlockSize = si.dwPageSize;
	intptr_t min = minAddr / BlockSize;
	intptr_t max = maxAddr / BlockSize;
	int rel = 0;
	m_trampoline = nullptr;
	MEMORY_BASIC_INFORMATION mi = { 0 };
	for (int i = 0; i < (max - min + 1); ++i)
	{
		rel = -rel + (i & 1);
		void* pQuery = reinterpret_cast<void*>(((min + max) / 2 + rel) * BlockSize);
		VirtualQuery(pQuery, &mi, sizeof(mi));
		if (mi.State == MEM_FREE)
		{
			m_trampoline = (unsigned char*)VirtualAlloc(pQuery, BlockSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (m_trampoline != nullptr)
				break;
		}
	}

	if (!m_trampoline)
		return;

	// save prologe hooked function
	*(ULONG64*)m_orgOpcode = *(ULONG64*)rtlThreadStartAddress;

	// the second illogical push rdx came here cause that i find that release build generate ThreadDeutor function
	// that starts with "mov qword ptr [rsp+8], rcx", which overwite rdx (which hold the thread parameter). so my 
	// workaround solution is to push rdx twice. 
	// But someone has an idea why the compiler tend to overwite outside from the frame stack? 
	// is it a part of x64 calling conversion?
	*(unsigned char*)	&m_trampoline[0] = 0x51;				// push rcx
	*(unsigned char*)	&m_trampoline[1] = 0x52;				// push rdx
	*(unsigned char*)	&m_trampoline[2] = 0x52;				// push rdx
	*(unsigned short*)	&m_trampoline[3] = 0x15FF;				// call
	*(DWORD*)			&m_trampoline[5] = 0x00000018;			//			ThreadDeutor
	*(unsigned char*)	&m_trampoline[9] = 0x5A;				// pop rdx
	*(unsigned char*)	&m_trampoline[10] = 0x5A;				// pop rdx
	*(unsigned char*)	&m_trampoline[11] = 0x59;				// pop rcx

	*(DWORD*)			&m_trampoline[12] = 0x48EC8348;			// sub rsp, 0x48	(2 instruction from prologe of target hook)
	*(unsigned short*)	&m_trampoline[16] = 0x8B4C;				// mov r9,
	*(unsigned char*)	&m_trampoline[18] = 0xC9;				//			rcx
	*(short*)			&m_trampoline[19] = 0x25FF;				// jmp
	*(DWORD*)			&m_trampoline[21] = 0x00000000;			//		rtlThreadStartAddress + 7

	// address data for call & jump
	*(DWORD64*)			&m_trampoline[25] = (DWORD64)((unsigned char*)rtlThreadStartAddress + 7);
	*(DWORD64*)			&m_trampoline[33] = (DWORD64)ThreadDeutor;

#else

	if (((unsigned char*)rtlThreadStartAddress)[0] != 0x89 || ((unsigned char*)rtlThreadStartAddress)[4] != 0x89 || ((unsigned char*)rtlThreadStartAddress)[8] != 0xE9)
		return;

	m_trampoline = (unsigned char*)VirtualAlloc(NULL, si.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!m_trampoline)
		return;

	// save prologe hooked function
	*(ULONG64*)m_orgOpcode = *(ULONG64*)rtlThreadStartAddress;

	*(unsigned char*) &m_trampoline[0] = 0x50;							// push eax
	*(unsigned char*) &m_trampoline[1] = 0x53;							// push ebx
	*(unsigned char*) &m_trampoline[2] = 0xE8;							// call
	*(unsigned long*) &m_trampoline[3] = (ULONG_PTR)ThreadDeutor - (ULONG_PTR)m_trampoline - 7;	//	ThreadDeutor
	*(unsigned char*) &m_trampoline[7] = 0x5B;							// pop ebx
	*(unsigned char*) &m_trampoline[8] = 0x58;							// pop eax

	// execute 2 instruction from prologe of hooked function
	*(unsigned long*)&m_trampoline[9] = *rtlThreadStartAddress;	
	*(unsigned long*)&m_trampoline[13] = *(rtlThreadStartAddress + 1);
	*(unsigned char*)&m_trampoline[17] = 0xE9;								// jmp
	*(unsigned long*)&m_trampoline[18] = (ULONG_PTR)rtlThreadStartAddress - (ULONG_PTR)m_trampoline - 14	//     rtlThreadStartAddress + 8


#endif
}

void HWBreakpoint::ToggleThreadHook(bool set)
{
	if (!m_trampoline)
		return;

	//TODO: replacing opcode in system dll might be dangeruos because another thread may invokes and run throw the code while we still replacing it.
	//		the right solution is to do it from another process which first suspend the target process, inject the changes to his memory, and resume it.

	DWORD oldProtect;
	ULONG_PTR* rtlThreadStartAddress = (ULONG_PTR*)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlUserThreadStart");

	if (set)
	{
		VirtualProtect(rtlThreadStartAddress, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
		((unsigned char*)rtlThreadStartAddress)[0] = 0xE9;
		*(DWORD*)&(((unsigned char*)rtlThreadStartAddress)[1]) = (DWORD)m_trampoline - (DWORD)rtlThreadStartAddress - 5;

		VirtualProtect(rtlThreadStartAddress, 5, oldProtect, &oldProtect);
	}
	else if (*rtlThreadStartAddress != *(ULONG_PTR*)m_orgOpcode)
	{
		VirtualProtect(rtlThreadStartAddress, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
		*(ULONG64*)rtlThreadStartAddress = *(ULONG64*)m_orgOpcode;
		VirtualProtect(rtlThreadStartAddress, 5, oldProtect, &oldProtect);
	}
}

void HWBreakpoint::ThreadDeutor()
{
	HWBreakpoint& bp = GetInstance();
	{
		CriticalSection::Scope lock(cs);
		
		bp.m_pendingThread.tid = GetCurrentThreadId();
		bp.m_pendingThread.enable = true;
		SetEvent(bp.m_workerSignal);
		WaitForSingleObject(bp.m_workerDone, INFINITE);
	}
}

void HWBreakpoint::SetForThreads()
{
	const DWORD pid = GetCurrentProcessId();

	HANDLE hThreadSnap = INVALID_HANDLE_VALUE; 
	THREADENTRY32 te32; 
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return;

	te32.dwSize = sizeof(THREADENTRY32); 
	if(!Thread32First(hThreadSnap, &te32))
	{
		CloseHandle(hThreadSnap);
		return;
	}

	do 
	{ 
		if(te32.th32OwnerProcessID == pid)
		{
			CriticalSection::Scope lock(cs);
			
			m_pendingThread.tid = te32.th32ThreadID;
			m_pendingThread.enable = true;
			SetEvent(m_workerSignal);
			WaitForSingleObject(m_workerDone, INFINITE);
		}
	} while(Thread32Next(hThreadSnap, &te32));
}

void HWBreakpoint::SetThread(DWORD tid, bool enableBP)
{
	// this function supposed to be called only from worker thread
	if (GetCurrentThreadId() == tid)
		return;

	HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |  THREAD_SUSPEND_RESUME, FALSE, tid);
	if (!hThread)
		return;

	do
	{
		CONTEXT cxt;
		cxt.ContextFlags = CONTEXT_DEBUG_REGISTERS;

		if (SuspendThread(hThread) == -1)
			break;

		if (!GetThreadContext(hThread, &cxt))
			break;

		for (int index = 0; index < 4; ++index)
		{
			const bool isSet = m_address[index] != nullptr;
			SetBits(cxt.Dr7, index*2, 1, isSet);

			if (isSet)
			{
				switch (index)
				{
				case 0: cxt.Dr0 = (DWORD_PTR) m_address[index]; break;
				case 1: cxt.Dr1 = (DWORD_PTR) m_address[index]; break;
				case 2: cxt.Dr2 = (DWORD_PTR) m_address[index]; break;
				case 3: cxt.Dr3 = (DWORD_PTR) m_address[index]; break;
				}

				SetBits(cxt.Dr7, 16 + (index*4), 2, m_when[index]);
				SetBits(cxt.Dr7, 18 + (index*4), 2, m_len[index]);
			}
		}

		if (!SetThreadContext(hThread, &cxt))
			break;

		if (ResumeThread(hThread) == -1)
			break;

		std::cout << "[HWBreakpoint] Set BP for Thread: " << tid << std::endl;

	} while (false);

	CloseHandle(hThread);
}

DWORD HWBreakpoint::WorkerThreadProc(LPVOID lpParameter)
{
	HWBreakpoint& bp = *(HWBreakpoint*)lpParameter;

	SetEvent(bp.m_workerDone);

	while (WaitForSingleObject(bp.m_workerSignal, INFINITE) == WAIT_OBJECT_0)
	{
		// signal for abort
		if (bp.m_pendingThread.tid == -1)
			return 0;

		bp.SetThread(bp.m_pendingThread.tid, bp.m_pendingThread.enable);
		SetEvent(bp.m_workerDone);
	}

	return 0;
}
