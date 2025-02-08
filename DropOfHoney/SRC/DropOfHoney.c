#ifdef _WIN64
// Minimal stub for stack probing if the compiler inserts ___chkstk_ms
__declspec(naked) void ___chkstk_ms(void)
{
    __asm__("ret");
}
#endif

#include <windows.h>
#include <activeds.h>
#include "DropOfHoney.h"
#include "beacon.h"

// ------------------------------------------------------------------------
// Simple case-insensitive compare to avoid _wcsicmp
static int MyWcsICmp(const wchar_t *s1, const wchar_t *s2)
{
    while (*s1 && *s2) {
        wchar_t c1 = *s1++;
        wchar_t c2 = *s2++;
        // convert uppercase A-Z to lowercase
        if (c1 >= L'A' && c1 <= L'Z') c1 += 32;
        if (c2 >= L'A' && c2 <= L'Z') c2 += 32;

        if (c1 != c2) {
            return (c1 - c2);
        }
    }
    return (*s1 - *s2);
}

// ------------------------------------------------------------------------
// Minimal wide-char copy/cat
static void custom_wcscpy(WCHAR *dest, const WCHAR *src)
{
    while ((*dest++ = *src++) != 0);
}
static void custom_wcscat(WCHAR *dest, const WCHAR *src)
{
    while (*dest) dest++;
    while ((*dest++ = *src++) != 0);
}

// ------------------------------------------------------------------------
// Helper to decode userAccountControl bits into a space-separated string
static void DecodeUAC(DWORD uac, WCHAR *outStr, size_t outSize)
{
    outStr[0] = 0;

    // Append a label for each bit if it's set
    if (uac & 0x0001)  custom_wcscat(outStr, L"SCRIPT ");
    if (uac & 0x0002)  custom_wcscat(outStr, L"ACCOUNTDISABLE ");
    if (uac & 0x0008)  custom_wcscat(outStr, L"HOMEDIR_REQUIRED ");
    if (uac & 0x0010)  custom_wcscat(outStr, L"LOCKOUT ");
    if (uac & 0x0020)  custom_wcscat(outStr, L"PASSWD_NOTREQD ");
    if (uac & 0x0040)  custom_wcscat(outStr, L"PASSWD_CANT_CHANGE ");
    if (uac & 0x0080)  custom_wcscat(outStr, L"ENCRYPTED_TEXT_PWD_ALLOWED ");
    if (uac & 0x0100)  custom_wcscat(outStr, L"TEMP_DUPLICATE_ACCOUNT ");
    if (uac & 0x0200)  custom_wcscat(outStr, L"NORMAL_ACCOUNT ");
    if (uac & 0x0800)  custom_wcscat(outStr, L"INTERDOMAIN_TRUST_ACCOUNT ");
    if (uac & 0x1000)  custom_wcscat(outStr, L"WORKSTATION_TRUST_ACCOUNT ");
    if (uac & 0x2000)  custom_wcscat(outStr, L"SERVER_TRUST_ACCOUNT ");
    if (uac & 0x10000) custom_wcscat(outStr, L"DONT_EXPIRE_PASSWORD ");
    if (uac & 0x20000) custom_wcscat(outStr, L"MNS_LOGON_ACCOUNT ");
    if (uac & 0x40000) custom_wcscat(outStr, L"SMARTCARD_REQUIRED ");
    if (uac & 0x80000) custom_wcscat(outStr, L"TRUSTED_FOR_DELEGATION ");
    if (uac & 0x100000) custom_wcscat(outStr, L"NOT_DELEGATED ");
    if (uac & 0x200000) custom_wcscat(outStr, L"USE_DES_KEY_ONLY ");
    if (uac & 0x400000) custom_wcscat(outStr, L"DONT_REQ_PREAUTH ");
    if (uac & 0x800000) custom_wcscat(outStr, L"PASSWORD_EXPIRED ");
    if (uac & 0x1000000) custom_wcscat(outStr, L"TRUSTED_TO_AUTH_FOR_DELEGATION ");
    if (uac & 0x4000000) custom_wcscat(outStr, L"PARTIAL_SECRETS_ACCOUNT ");

}


// ------------------------------------------------------------------------
// Convert LARGE_INTEGER AD time -> local date/time (string)
static void ConvertLargeIntToString(LARGE_INTEGER liTime, WCHAR *outStr, size_t maxChars)
{
    outStr[0] = 0;

    FILETIME ftLocal;
    ftLocal.dwLowDateTime  = liTime.LowPart;
    ftLocal.dwHighDateTime = liTime.HighPart;

    if (ftLocal.dwLowDateTime == 0 && ftLocal.dwHighDateTime == 0) {
        custom_wcscpy(outStr, L"Never");
        return;
    }

    if (!KERNEL32$FileTimeToLocalFileTime(&ftLocal, &ftLocal)) {
        custom_wcscpy(outStr, L"[FileTimeToLocalFileTime Error]");
        return;
    }
    SYSTEMTIME stLocal;
    if (!KERNEL32$FileTimeToSystemTime(&ftLocal, &stLocal)) {
        custom_wcscpy(outStr, L"[FileTimeToSystemTime Error]");
        return;
    }

    DATE date;
    if (!OLEAUT32$SystemTimeToVariantTime(&stLocal, &date)) {
        custom_wcscpy(outStr, L"[SystemTimeToVariantTime Error]");
        return;
    }
    VARIANT varDate;
    OLEAUT32$VariantInit(&varDate);
    varDate.vt   = VT_DATE;
    varDate.date = date;
    if (SUCCEEDED(OLEAUT32$VariantChangeType(&varDate, &varDate, 0, VT_BSTR))) {
        custom_wcscpy(outStr, varDate.bstrVal);
    } else {
        custom_wcscpy(outStr, L"[VariantChangeType Error]");
    }
    OLEAUT32$VariantClear(&varDate);
}

// ------------------------------------------------------------------------
// Convert ADSTYPE_UTC_TIME -> local time string
static void UtcSystemTimeToString(SYSTEMTIME stUTC, WCHAR *outStr, size_t maxChars)
{
    outStr[0] = 0;

    FILETIME ftUTC, ftLocal;
    if (!KERNEL32$SystemTimeToFileTime(&stUTC, &ftUTC)) {
        custom_wcscpy(outStr, L"[SystemTimeToFileTime Error]");
        return;
    }
    if (!KERNEL32$FileTimeToLocalFileTime(&ftUTC, &ftLocal)) {
        custom_wcscpy(outStr, L"[FileTimeToLocalFileTime Error]");
        return;
    }
    SYSTEMTIME stLocal;
    if (!KERNEL32$FileTimeToSystemTime(&ftLocal, &stLocal)) {
        custom_wcscpy(outStr, L"[FileTimeToSystemTime Error]");
        return;
    }

    DATE date;
    if (!OLEAUT32$SystemTimeToVariantTime(&stLocal, &date)) {
        custom_wcscpy(outStr, L"[SystemTimeToVariantTime Error]");
        return;
    }
    VARIANT varDate;
    OLEAUT32$VariantInit(&varDate);
    varDate.vt   = VT_DATE;
    varDate.date = date;
    if (SUCCEEDED(OLEAUT32$VariantChangeType(&varDate, &varDate, 0, VT_BSTR))) {
        custom_wcscpy(outStr, varDate.bstrVal);
    } else {
        custom_wcscpy(outStr, L"[VariantChangeType Error]");
    }
    OLEAUT32$VariantClear(&varDate);
}

// ------------------------------------------------------------------------
// Fill in fields in USER_INFO struct 
static void HandleLargeIntegerAttribute(PUSER_INFO pui, LPCWSTR attrName, LARGE_INTEGER liTime)
{
    if (MyWcsICmp(attrName, L"lastLogonTimestamp") == 0 && !pui->bHaveLastLogon) {
        ConvertLargeIntToString(liTime, pui->lastLogonTimestamp, 128);
        pui->bHaveLastLogon = TRUE;
    } else if (MyWcsICmp(attrName, L"pwdLastSet") == 0 && !pui->bHavePwdLastSet) {
        ConvertLargeIntToString(liTime, pui->pwdLastSet, 128);
        pui->bHavePwdLastSet = TRUE;
    }
}

static void HandleUtcTimeAttribute(PUSER_INFO pui, LPCWSTR attrName, SYSTEMTIME stUTC)
{
    if (MyWcsICmp(attrName, L"whenCreated") == 0 && !pui->bHaveWhenCreated) {
        UtcSystemTimeToString(stUTC, pui->whenCreated, 128);
        pui->bHaveWhenCreated = TRUE;
    }
}

static void HandleIntegerAttribute(PUSER_INFO pui, LPCWSTR attrName, DWORD val)
{
    if (MyWcsICmp(attrName, L"userAccountControl") == 0 && !pui->bHaveUAC) {
        pui->uacValue = val;
        pui->bHaveUAC = TRUE;
    }
}

static void HandleStringAttribute(PUSER_INFO pui, LPCWSTR attrName, LPCWSTR valStr)
{
    // e.g. description, sAMAccountName, whenCreated if stored as string
    if (MyWcsICmp(attrName, L"description") == 0 && !pui->bHaveDescription) {
        custom_wcscpy(pui->description, valStr);
        pui->bHaveDescription = TRUE;
    } else if (MyWcsICmp(attrName, L"sAMAccountName") == 0 && !pui->bHaveSamAccountName) {
        custom_wcscpy(pui->samAccountName, valStr);
        pui->bHaveSamAccountName = TRUE;
    } else if (MyWcsICmp(attrName, L"whenCreated") == 0 && !pui->bHaveWhenCreated) {
        custom_wcscpy(pui->whenCreated, valStr);
        pui->bHaveWhenCreated = TRUE;
    }
}

// Zero out the struct
static void InitUserInfo(PUSER_INFO pui)
{
    MSVCRT$memset(pui, 0, sizeof(USER_INFO));
}



// ------------------------------------------------------------------------
// Query the attributes, store them in USER_INFO
HRESULT QueryUserAttributes(IDirectorySearch *pContainer, LPCWSTR lpwFilter)
{
    WCHAR bigOutput[4096];
    bigOutput[0] = 0;

    if (!pContainer) {
        custom_wcscat(bigOutput, L"[ERROR] pContainer is NULL.\n");
        BeaconPrintf(CALLBACK_OUTPUT, "%ls", bigOutput);
        return E_POINTER;
    }

    // 1) Set subtree preference
    ADS_SEARCHPREF_INFO pref;
    pref.dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    pref.vValue.dwType = ADSTYPE_INTEGER;
    pref.vValue.Integer = ADS_SCOPE_SUBTREE;

    HRESULT hr = pContainer->lpVtbl->SetSearchPreference(pContainer, &pref, 1);
    if (FAILED(hr)) {
        WCHAR tmp[256];
        MSVCRT$swprintf_s(tmp, 256, L"[ERROR] SetSearchPreference failed: 0x%08lx\n", hr);
        custom_wcscat(bigOutput, tmp);
        BeaconPrintf(CALLBACK_OUTPUT, "%ls", bigOutput);
        return hr;
    }

    // 2) We want these attributes
    LPCWSTR attrs[] = {
        L"description",
        L"sAMAccountName",
        L"lastLogonTimestamp",
        L"pwdLastSet",
        L"whenCreated",
        L"userAccountControl"
    };

    // 3) Build filter with (sAMAccountName=lpwFilter)
    WCHAR wcFilter[512];
    MSVCRT$swprintf_s(wcFilter, 512,
        L"(|(&(objectCategory=person)(objectClass=user)(sAMAccountName=%ls))"
        L"(&(objectCategory=computer)(objectClass=computer)(sAMAccountName=%ls$)))",
        lpwFilter, lpwFilter
    );


    // 4) Execute search
    ADS_SEARCH_HANDLE hSearch = NULL;
    hr = pContainer->lpVtbl->ExecuteSearch(
        pContainer,
        wcFilter,
        (LPWSTR*)attrs,
        6,
        &hSearch
    );
    if (FAILED(hr)) {
        WCHAR tmp[256];
        MSVCRT$swprintf_s(tmp, 256, L"[ERROR] ExecuteSearch: 0x%08lx\n", hr);
        custom_wcscat(bigOutput, tmp);
        BeaconPrintf(CALLBACK_OUTPUT, "%ls", bigOutput);
        return hr;
    }

    // 5) Prepare a USER_INFO struct to hold the data
    USER_INFO ui;
    InitUserInfo(&ui);

    int rowCount = 0;
    hr = pContainer->lpVtbl->GetFirstRow(pContainer, hSearch);
    while (hr != S_ADS_NOMORE_ROWS && SUCCEEDED(hr)) {
        rowCount++;

        LPWSTR pszColumn = NULL;
        while (pContainer->lpVtbl->GetNextColumnName(pContainer, hSearch, &pszColumn) != S_ADS_NOMORE_COLUMNS)
        {
            if (!pszColumn) break;

            ADS_SEARCH_COLUMN col;
            HRESULT hrCol = pContainer->lpVtbl->GetColumn(pContainer, hSearch, pszColumn, &col);
            if (SUCCEEDED(hrCol)) {
                // store if not already set
                switch (col.dwADsType) {
                case ADSTYPE_LARGE_INTEGER:
                    for (DWORD i=0; i<col.dwNumValues; i++) {
                        HandleLargeIntegerAttribute(&ui, pszColumn, col.pADsValues[i].LargeInteger);
                    }
                    break;
                case ADSTYPE_UTC_TIME:
                    for (DWORD i=0; i<col.dwNumValues; i++) {
                        HandleUtcTimeAttribute(&ui, pszColumn, col.pADsValues[i].UTCTime);
                    }
                    break;
                case ADSTYPE_INTEGER:
                    for (DWORD i=0; i<col.dwNumValues; i++) {
                        HandleIntegerAttribute(&ui, pszColumn, col.pADsValues[i].Integer);
                    }
                    break;
                case ADSTYPE_CASE_IGNORE_STRING:
                case ADSTYPE_CASE_EXACT_STRING:
                case ADSTYPE_PRINTABLE_STRING:
                    for (DWORD i=0; i<col.dwNumValues; i++) {
                        HandleStringAttribute(&ui, pszColumn, col.pADsValues[i].CaseIgnoreString);
                    }
                    break;
                default:
                    break;
                }
                pContainer->lpVtbl->FreeColumn(pContainer, &col);
            }

            // free column name
            HMODULE hActiveds = GetModuleHandleA("Activeds.dll");
            if (hActiveds) {
                _FreeADsMem FreeADsMemFn = (_FreeADsMem)GetProcAddress(hActiveds, "FreeADsMem");
                if (FreeADsMemFn) {
                    FreeADsMemFn(pszColumn);
                }
            }
        }
        // Next row
        hr = pContainer->lpVtbl->GetNextRow(pContainer, hSearch);
    }

    pContainer->lpVtbl->CloseSearchHandle(pContainer, hSearch);

    // 6) Summarize results in bigOutput
    if (rowCount == 0) {
        custom_wcscat(bigOutput, L"[!] No matching user found.\n");
    } else {

        if (ui.bHaveSamAccountName) {
            WCHAR line[512];
            MSVCRT$swprintf_s(line, 512, L"[+] sAMAccountName: %ls\n", ui.samAccountName);
            custom_wcscat(bigOutput, line);
        }
        if (ui.bHaveDescription) {
            WCHAR line[512];
            MSVCRT$swprintf_s(line, 512, L"[+] description: %ls\n", ui.description);
            custom_wcscat(bigOutput, line);
        }
        if (ui.bHaveUAC) {
            WCHAR line[512];
            MSVCRT$swprintf_s(line, 512, L"[+] userAccountControl: %u\n", ui.uacValue);
            custom_wcscat(bigOutput, line);

            // decode bits
            WCHAR bits[512];
            bits[0] = 0;
            DecodeUAC(ui.uacValue, bits, 512);
            if (bits[0]) {
                WCHAR line2[512];
                MSVCRT$swprintf_s(line2, 512, L"    bits: %ls\n", bits);
                custom_wcscat(bigOutput, line2);
            }
            if (ui.uacValue & 0x0002) {
                custom_wcscat(bigOutput, L"    [Account is DISABLED]\n");
            } else {
                custom_wcscat(bigOutput, L"    [Account is ENABLED]\n");
            }
        }
        if (ui.bHaveLastLogon) {
            WCHAR line[512];
            MSVCRT$swprintf_s(line, 512, L"[+] lastLogonTimestamp: %ls\n", ui.lastLogonTimestamp);
            custom_wcscat(bigOutput, line);
        } else {
            custom_wcscat(bigOutput, L"[+] lastLogonTimestamp: NOT RETURNED => likely never logged in\n");
        }
        if (ui.bHavePwdLastSet) {
            WCHAR line[512];
            MSVCRT$swprintf_s(line, 512, L"[+] pwdLastSet: %ls\n", ui.pwdLastSet);
            custom_wcscat(bigOutput, line);
        }
        if (ui.bHaveWhenCreated) {
            WCHAR line[512];
            MSVCRT$swprintf_s(line, 512, L"[+] whenCreated: %ls\n", ui.whenCreated);
            custom_wcscat(bigOutput, line);
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "%ls", bigOutput);
    return S_OK;
}

// ------------------------------------------------------------------------
// BOF Entry
void go(char *args, int length)
{
    // 1) Load Activeds.dll
    HMODULE hActiveds = LoadLibraryA("Activeds.dll");
    if (!hActiveds) {
        BeaconPrintf(CALLBACK_ERROR, "[ERROR] Failed to load Activeds.dll");
        return;
    }
    _ADsOpenObject ADsOpenObjectFn = (_ADsOpenObject)GetProcAddress(hActiveds, "ADsOpenObject");
    if (!ADsOpenObjectFn) {
        BeaconPrintf(CALLBACK_ERROR, "[ERROR] Could not get ADsOpenObject");
        return;
    }

    // 2) Initialize COM
    HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[ERROR] CoInitializeEx: 0x%08lx", hr);
        return;
    }

    // 3) Parse arg => sAMAccountName
    datap parser;
    BeaconDataParse(&parser, args, length);
    wchar_t * userName = (wchar_t *)BeaconDataExtract(&parser, NULL);
    if (!userName || !userName[0]) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: DropOfHoney <sAMAccountName>");
        goto Cleanup;
    }

    // 4) Resolve IIDs
    IID IID_IADs, IID_IDirectorySearch;
    OLE32$IIDFromString(L"{FD8256D0-FD15-11CE-ABC4-02608C9E7553}", &IID_IADs);
    OLE32$IIDFromString(L"{109BA8EC-92F0-11D0-A790-00C04FD8D5A8}", &IID_IDirectorySearch);

    // 5) Bind LDAP://rootDSE
    IADs *pRootDSE = NULL;
    hr = ADsOpenObjectFn(
        L"LDAP://rootDSE",
        NULL,
        NULL,
        ADS_SECURE_AUTHENTICATION,
        &IID_IADs,
        (void**)&pRootDSE
    );
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[ERROR] Bind rootDSE: 0x%08lx", hr);
        goto Cleanup;
    }

    // 6) Get defaultNamingContext
    VARIANT varCtx;
    OLEAUT32$VariantInit(&varCtx);
    hr = pRootDSE->lpVtbl->Get(pRootDSE, (BSTR)L"defaultNamingContext", &varCtx);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[ERROR] defaultNamingContext: 0x%08lx", hr);
        goto Cleanup;
    }

    // 7) Build "LDAP://<defaultNamingContext>"
    WCHAR wcPath[512];
    MSVCRT$memset(wcPath, 0, sizeof(wcPath));
    custom_wcscpy(wcPath, L"LDAP://");
    custom_wcscat(wcPath, varCtx.bstrVal);

    // 8) Bind IDirectorySearch
    IDirectorySearch *pSearch = NULL;
    hr = ADsOpenObjectFn(
        wcPath,
        NULL,
        NULL,
        ADS_SECURE_AUTHENTICATION,
        &IID_IDirectorySearch,
        (void**)&pSearch
    );
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[ERROR] Bind container %ls: 0x%08lx", wcPath, hr);
        goto Cleanup;
    }

    // 9) Query
    QueryUserAttributes(pSearch, userName);

    // 10) Release
    pSearch->lpVtbl->Release(pSearch);
    pSearch = NULL;

Cleanup:
    OLEAUT32$VariantClear(&varCtx);
    if (pRootDSE) {
        pRootDSE->lpVtbl->Release(pRootDSE);
        pRootDSE = NULL;
    }
    OLE32$CoUninitialize();
}
