#pragma once

#include <windows.h>
#include <activeds.h>

// ------------------------------------------------------------------------
// BOF environment declarations

// OLE32
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
DECLSPEC_IMPORT void    WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$IIDFromString(LPCOLESTR lpsz, LPIID lpiid);

// OLEAUT32
DECLSPEC_IMPORT void    WINAPI OLEAUT32$VariantInit(VARIANTARG *pvarg);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$VariantClear(VARIANTARG *pvarg);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$VariantChangeType(VARIANTARG *pvargDest, const VARIANTARG *pvarSrc, USHORT wFlags, VARTYPE vt);
DECLSPEC_IMPORT INT     WINAPI OLEAUT32$SystemTimeToVariantTime(LPSYSTEMTIME lpSystemTime, DOUBLE *pvtime);

// KERNEL32
WINBASEAPI BOOL WINAPI  KERNEL32$FileTimeToLocalFileTime(CONST FILETIME *lpFileTime, LPFILETIME lpLocalFileTime);
WINBASEAPI BOOL WINAPI  KERNEL32$FileTimeToSystemTime(CONST FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);

// MSVCRT
WINBASEAPI int __cdecl  MSVCRT$swprintf_s(
    wchar_t *buffer,
    size_t sizeOfBuffer,
    const wchar_t *format,
    ...
);
WINBASEAPI void * __cdecl MSVCRT$memset(void *dest, int c, size_t count);

WINBASEAPI BOOL WINAPI KERNEL32$SystemTimeToFileTime(
    CONST SYSTEMTIME *lpSystemTime,
    LPFILETIME lpFileTime
);

// ActiveDS
typedef HRESULT (WINAPI *_ADsOpenObject)(
    LPCWSTR lpszPathName,
    LPCWSTR lpszUserName,
    LPCWSTR lpszPassword,
    DWORD dwReserved,
    REFIID riid,
    void **ppObject
);
typedef BOOL (WINAPI *_FreeADsMem)(LPVOID pMem);

typedef struct _USER_INFO {
    // booleans indicating if we already set a field
    BOOL  bHaveDescription;
    BOOL  bHaveSamAccountName;
    BOOL  bHaveLastLogon;
    BOOL  bHavePwdLastSet;
    BOOL  bHaveWhenCreated;
    BOOL  bHaveUAC;

    // storage for each attribute's data
    WCHAR description[512];
    WCHAR samAccountName[256];
    WCHAR lastLogonTimestamp[128];
    WCHAR pwdLastSet[128];
    WCHAR whenCreated[128];
    DWORD uacValue;
} USER_INFO, *PUSER_INFO;
