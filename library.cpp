#include <set>
#include "Windows.h"

/**
 * x86
 * E9 JMP FFAABBBB
 * E8 CALL
 */
#ifdef  _M_IX86
#define  BYTE_LEN 5
BYTE targetBytes[]{0xE9, 0x00, 0x00, 0x00, 0x00};
BYTE originalBytes[BYTE_LEN]{};
#endif
/**
 * x64
 * 48 B8 DDDDCCCCBBBBAA00 MOV RAX,00AABBBBCCCCDDDD
 * FF E0 JMP RAX
 */
#ifdef  _M_X64
#define  BYTE_LEN 12
BYTE targetBytes[]{0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0};
BYTE originalBytes[BYTE_LEN]{};
#endif

HANDLE hprocess;
LPVOID originalPfn;
std::set<DWORD> protectionProcessIds;// 需要保护的pid集合

void initProtection()
{
    protectionProcessIds.insert(30908);
    protectionProcessIds.insert(11668);
}

HANDLE WINAPI TargetOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
    if (protectionProcessIds.count(dwProcessId) > 0) {
        return NULL;
    }

    DWORD dwOldProtect, dwNewProtect;
    SIZE_T dwNum = 0;

    VirtualProtectEx(hprocess, originalPfn, BYTE_LEN, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    WriteProcessMemory(GetCurrentProcess(), originalPfn, originalBytes, BYTE_LEN, &dwNum);// UN
    HANDLE handle = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    WriteProcessMemory(GetCurrentProcess(), originalPfn, targetBytes, BYTE_LEN, &dwNum);// RE
    VirtualProtectEx(hprocess, originalPfn, BYTE_LEN, dwOldProtect, &dwNewProtect);

    return handle;
}

BOOL HookModuleFn(const char *szModuleName, const char *szFuncName, PROC pFn)
{
    if (protectionProcessIds.empty()) {
        return FALSE;
    }

    originalPfn = (LPVOID) ::GetProcAddress(::GetModuleHandle(szModuleName), szFuncName);
    if (!originalPfn) {
        return FALSE;
    }

    hprocess = GetCurrentProcess();
    SIZE_T dwNum = 0;
    ReadProcessMemory(hprocess, originalPfn, originalBytes, BYTE_LEN, &dwNum);

#ifdef  _M_IX86
    *(DWORD *) (targetBytes + 1) = (DWORD) pFn - (DWORD) originalPfn - BYTE_LEN;
#endif
#ifdef  _M_X64
    *(DWORD *) (targetBytes + 2) = (INT64) pFn;
#endif

    DWORD dwOldProtect, dwNewProtect;
    VirtualProtectEx(hprocess, originalPfn, BYTE_LEN, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    WriteProcessMemory(GetCurrentProcess(), originalPfn, targetBytes, BYTE_LEN, &dwNum);
    VirtualProtectEx(hprocess, originalPfn, BYTE_LEN, dwOldProtect, &dwNewProtect);

    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        initProtection();
        HookModuleFn("kernel32.dll", "OpenProcess", (PROC) TargetOpenProcess);
    }
    return TRUE;
}
