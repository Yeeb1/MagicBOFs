#pragma once

#include <windows.h>
#include <activeds.h>
#include <psapi.h>

// ------------------------------------------------------------------------
// BOF environment declarations

// KERNEL32
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Module32First(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Module32Next(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleW(LPCWSTR lpModuleName);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);

// ADVAPI32
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);

// NTDLL
typedef LONG (WINAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtDelayExecution(BOOL Alertable, PLARGE_INTEGER DelayInterval);

// MSCRT
WINBASEAPI void * __cdecl MSVCRT$memcpy(void *dest, const void *src, size_t count);
WINBASEAPI void * __cdecl MSVCRT$memmove(void *dest, const void *src, size_t count);
WINBASEAPI void * __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI int    __cdecl MSVCRT$memcmp(const void *buf1, const void *buf2, size_t count);
WINBASEAPI int    __cdecl MSVCRT$sprintf(char *buffer, const char *format, ...);
WINBASEAPI int    __cdecl MSVCRT$strlen(const char *str);
WINBASEAPI int    __cdecl MSVCRT$strcmp(const char *s1, const char *s2);
WINBASEAPI char * __cdecl MSVCRT$strchr(const char *str, int c);
WINBASEAPI char * __cdecl MSVCRT$strstr(const char *haystack, const char *needle);
WINBASEAPI char * __cdecl MSVCRT$strcat(char *dest, const char *src);
WINBASEAPI char * __cdecl MSVCRT$strcpy(char *dest, const char *src);


// Structs
typedef struct _PATCH_PATTERN {
    DWORD Length;
    BYTE *Pattern;
} PATCH_PATTERN, *PPATCH_PATTERN;

typedef struct _PATCH_OFFSETS {
    LONG off0;
} PATCH_OFFSETS, *PPATCH_OFFSETS;

typedef struct _PATCH_GENERIC {
    DWORD MinBuildNumber;
    PATCH_PATTERN Search;
    PATCH_PATTERN Patch;
    PATCH_OFFSETS Offsets;
} PATCH_GENERIC, *PPATCH_GENERIC;

typedef struct _dll_info {
    int  pid;
    byte *dll_addr;
    int  dll_size;
} dll_info;
