#ifdef _WIN64
// Minimal stub for stack probing if the compiler inserts ___chkstk_ms
__declspec(naked) void ___chkstk_ms(void)
{
    __asm__("ret");
}
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include "beacon.h"
#include "TappingAtTheWindow.h"


// Default User-Agent (Microsoft Edge)
const char *DEFAULT_USER_AGENT =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0";


// Remove surrounding quotes from a string for better argument parsing
void remove_quotes(wchar_t *str) {
    if (!str) return;
    size_t len = MSVCRT$wcslen(str);
    if (len > 1 && str[0] == L'"' && str[len - 1] == L'"') {
        str[len - 1] = L'\0'; 
        MSVCRT$memmove(str, str + 1, len * sizeof(wchar_t)); 
    }
}

void convertToWideChar(const char *src, wchar_t *dest, size_t destSize) {
    if (!src || !dest) return;

    size_t i;
    for (i = 0; i < destSize - 1 && src[i] != '\0'; i++) {
        dest[i] = (wchar_t)(unsigned char)src[i];  // Simple ASCII to wide-char conversion
    }
    dest[i] = L'\0';  // Ensure null termination
}


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


// Extract <title> from HTML response
void extract_title(const char *html, formatp *fmt) {
    const char *start = MSVCRT$strstr(html, "<title>");
    if (!start) {
        BeaconFormatPrintf(fmt, "[-] No <title> found.\n");
        return;
    }
    start += 7; // Skip "<title>"
    const char *end = MSVCRT$strstr(start, "</title>");
    if (!end) {
        BeaconFormatPrintf(fmt, "[-] No closing </title> found.\n");
        return;
    }
    char title[256];
    size_t titleLen = end - start;
    if (titleLen >= sizeof(title))
        titleLen = sizeof(title) - 1;
    MSVCRT$memcpy(title, start, titleLen);
    title[titleLen] = '\0';
    BeaconFormatPrintf(fmt, "[+] Page Title\t\t: %s\n", title);
}

// Append TLS Certificate Information to format buffer
void print_cert_info(PCCERT_CONTEXT pCertContext, formatp *fmt) {
    if (!pCertContext) {
        BeaconFormatPrintf(fmt, "[-] No certificate found.\n");
        return;
    }
    char subjectName[256] = {0};
    DWORD subjectSize = CRYPT32$CertGetNameStringA(
        pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL,
        subjectName, sizeof(subjectName)
    );
    if (subjectSize > 1)
        BeaconFormatPrintf(fmt, "[+] TLS Certificate Subject: %s\n", subjectName);
    char issuerName[256] = {0};
    DWORD issuerSize = CRYPT32$CertGetNameStringA(
        pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL,
        issuerName, sizeof(issuerName)
    );
    if (issuerSize > 1)
        BeaconFormatPrintf(fmt, "[+] TLS Certificate Issuer\t: %s\n", issuerName);
    SYSTEMTIME stNotBefore, stNotAfter;
    if (KERNEL32$FileTimeToSystemTime(&pCertContext->pCertInfo->NotBefore, &stNotBefore) &&
        KERNEL32$FileTimeToSystemTime(&pCertContext->pCertInfo->NotAfter, &stNotAfter)) {
        BeaconFormatPrintf(fmt, "[+] Valid From\t\t: %02d/%02d/%04d\n",
            stNotBefore.wDay, stNotBefore.wMonth, stNotBefore.wYear);
        BeaconFormatPrintf(fmt, "[+] Valid Until\t\t: %02d/%02d/%04d\n",
            stNotAfter.wDay, stNotAfter.wMonth, stNotAfter.wYear);
    }
}


void doFinger(const wchar_t *url, const wchar_t *userAgent) {
    formatp fmt;
    BeaconFormatAlloc(&fmt, 4096);

    // Parse URL components.
    URL_COMPONENTS urlComp;
    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    wchar_t hostName[256] = {0};
    wchar_t urlPath[512] = {0};
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = 256;
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = 512;

    if (!WINHTTP$WinHttpCrackUrl(url, 0, 0, &urlComp)) {
        BeaconFormatPrintf(&fmt, "[-] Failed to parse URL.\n");
        goto out;
    }

    HINTERNET hSession = WINHTTP$WinHttpOpen(userAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) {
        BeaconFormatPrintf(&fmt, "[-] WinHttpOpen failed.\n");
        goto out;
    }

    HINTERNET hConnect = WINHTTP$WinHttpConnect(hSession, hostName, urlComp.nPort, 0);
    if (!hConnect) {
        BeaconFormatPrintf(&fmt, "[-] WinHttpConnect failed.\n");
        WINHTTP$WinHttpCloseHandle(hSession);
        goto out;
    }

    HINTERNET hRequest = WINHTTP$WinHttpOpenRequest(hConnect, L"GET", urlComp.lpszUrlPath, NULL, NULL, NULL,
        (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        BeaconFormatPrintf(&fmt, "[-] WinHttpOpenRequest failed.\n");
        WINHTTP$WinHttpCloseHandle(hConnect);
        WINHTTP$WinHttpCloseHandle(hSession);
        goto out;
    }

    if (!WINHTTP$WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0)) {
        BeaconFormatPrintf(&fmt, "[-] WinHttpSendRequest failed.\n");
        goto cleanup;
    }

    if (!WINHTTP$WinHttpReceiveResponse(hRequest, NULL)) {
        BeaconFormatPrintf(&fmt, "[-] WinHttpReceiveResponse failed.\n");
        goto cleanup;
    }

    // Retrieve response headers dynamically
    {
        DWORD headerSize = 0;
        WINHTTP$WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, NULL, NULL, &headerSize, NULL);

        if (headerSize == 0) {
            BeaconFormatPrintf(&fmt, "[-] Headers size is unavailable.\n");
            goto cleanup;
        }

        // Allocate buffer dynamically based on required size
        wchar_t *wHeadersBuffer = (wchar_t *) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, headerSize);
        if (!wHeadersBuffer) {
            BeaconFormatPrintf(&fmt, "[-] Failed to allocate memory for headers.\n");
            goto cleanup;
        }

        if (WINHTTP$WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, NULL, wHeadersBuffer, &headerSize, NULL)) {
            DWORD convSize = KERNEL32$WideCharToMultiByte(CP_ACP, 0, wHeadersBuffer, -1, NULL, 0, NULL, NULL);
            if (convSize > 0) {
                char *aHeadersBuffer = (char *) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, convSize);
                if (aHeadersBuffer) {
                    KERNEL32$WideCharToMultiByte(CP_ACP, 0, wHeadersBuffer, -1, aHeadersBuffer, convSize, NULL, NULL);
                    BeaconFormatPrintf(&fmt, "[+] Response Headers:\n%s\n", aHeadersBuffer);
                    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, aHeadersBuffer);
                } else {
                    BeaconFormatPrintf(&fmt, "[-] Failed to allocate memory for ANSI headers.\n");
                }
            } else {
                BeaconFormatPrintf(&fmt, "[-] Failed to convert headers to ANSI.\n");
            }
        } else {
            BeaconFormatPrintf(&fmt, "[-] Failed to retrieve headers (Error %lu)\n", KERNEL32$GetLastError());
        }

        // Free dynamically allocated memory
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, wHeadersBuffer);
    }

    // If HTTPS, query for the certificate
    if (urlComp.nScheme == INTERNET_SCHEME_HTTPS) {
        PCCERT_CONTEXT pCertContext = NULL;
        DWORD certSize = sizeof(pCertContext);
        if (WINHTTP$WinHttpQueryOption(hRequest, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &pCertContext, &certSize)) {
            print_cert_info(pCertContext, &fmt);
            CRYPT32$CertFreeCertificateContext(pCertContext);
        } else {
            BeaconFormatPrintf(&fmt, "[-] Failed to retrieve TLS certificate.\n");
        }
    }

    // Read HTML and extract <title>
    {
        char buffer[8192];
        DWORD bytesRead = 0;
        if (WINHTTP$WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            extract_title(buffer, &fmt);
        } else {
            BeaconFormatPrintf(&fmt, "[-] Failed to read HTML data.\n");
        }
    }

cleanup:
    WINHTTP$WinHttpCloseHandle(hRequest);
    WINHTTP$WinHttpCloseHandle(hConnect);
    WINHTTP$WinHttpCloseHandle(hSession);

out:
    int outSize = 0;
    char *outStr = BeaconFormatToString(&fmt, &outSize);
    BeaconOutput(CALLBACK_OUTPUT, outStr, outSize);
    BeaconFormatFree(&fmt);
}



// Print: read and output response in chunks
// using a fixed-size buffer to stream output, ugly but easier to transport

void doPrint(const wchar_t *url, const wchar_t *userAgent) {
    HINTERNET hSession, hConnect, hRequest;
    URL_COMPONENTS urlComp;
    wchar_t hostName[256] = {0}, urlPath[512] = {0};


    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = 256;
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = 512;
    if (!WINHTTP$WinHttpCrackUrl(url, 0, 0, &urlComp)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to parse URL.\n");
        return;
    }

    hSession = WINHTTP$WinHttpOpen(userAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] WinHttpOpen failed.\n");
        return;
    }

    // Optionally set redirection if needed
    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    WINHTTP$WinHttpSetOption(hSession, WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy, sizeof(redirectPolicy));

    hConnect = WINHTTP$WinHttpConnect(hSession, hostName, urlComp.nPort, 0);
    if (!hConnect) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] WinHttpConnect failed.\n");
        WINHTTP$WinHttpCloseHandle(hSession);
        return;
    }

    hRequest = WINHTTP$WinHttpOpenRequest(hConnect, L"GET", urlComp.lpszUrlPath, NULL, NULL, NULL,
        (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] WinHttpOpenRequest failed.\n");
        WINHTTP$WinHttpCloseHandle(hConnect);
        WINHTTP$WinHttpCloseHandle(hSession);
        return;
    }

    if (!WINHTTP$WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] WinHttpSendRequest failed.\n");
        WINHTTP$WinHttpCloseHandle(hRequest);
        WINHTTP$WinHttpCloseHandle(hConnect);
        WINHTTP$WinHttpCloseHandle(hSession);
        return;
    }

    if (!WINHTTP$WinHttpReceiveResponse(hRequest, NULL)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] WinHttpReceiveResponse failed.\n");
        WINHTTP$WinHttpCloseHandle(hRequest);
        WINHTTP$WinHttpCloseHandle(hConnect);
        WINHTTP$WinHttpCloseHandle(hSession);
        return;
    }

    // Stream response in fixed-size chunks (1024 bytes)
    char szBuffer[1024];
    DWORD dwRead = 0;
    while (WINHTTP$WinHttpReadData(hRequest, szBuffer, sizeof(szBuffer) - 1, &dwRead) && dwRead > 0) {
        szBuffer[dwRead] = '\0';
        BeaconPrintf(CALLBACK_OUTPUT, "%s", szBuffer);
        dwRead = 0;
    }

    WINHTTP$WinHttpCloseHandle(hRequest);
    WINHTTP$WinHttpCloseHandle(hConnect);
    WINHTTP$WinHttpCloseHandle(hSession);

}



// Expected format: <command> <url> [user-agent]
void go(char *args, int length) {
    datap parser;
    BeaconDataParse(&parser, args, length);

    // Extract arguments
    wchar_t *cmd = (wchar_t *)BeaconDataExtract(&parser, NULL);
    wchar_t *urlArg = (wchar_t *)BeaconDataExtract(&parser, NULL);
    wchar_t *uaArg = NULL;
    size_t uaLength = 0;
    wchar_t *temp = NULL;

    // Rebuild the user-agent from remaining arguments
    while ((temp = (wchar_t *)BeaconDataExtract(&parser, NULL)) != NULL) {
        size_t tempLen = MSVCRT$wcslen(temp);
        if (!uaArg) {
            uaArg = (wchar_t *)MSVCRT$calloc(tempLen + 1, sizeof(wchar_t));
        } else {
            uaArg = (wchar_t *)MSVCRT$realloc(uaArg, (uaLength + tempLen + 2) * sizeof(wchar_t));
            MSVCRT$wcscat(uaArg, L" "); 
        }
        MSVCRT$wcscat(uaArg, temp); 
        uaLength += tempLen + 1;
    }

    // Defaulting if BOF is used without cna
    if (!uaArg) {
        static wchar_t wDefaultUA[256];
        convertToWideChar(DEFAULT_USER_AGENT, wDefaultUA, 256);
        uaArg = wDefaultUA;
    }

    if (!cmd || !urlArg) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Missing required arguments: <command> <url> [user-agent]");
        return;
    }

    // Remove surrounding quotes from URL and User-Agent (internally)
    remove_quotes(urlArg);
    remove_quotes(uaArg);

    static wchar_t wDefaultUA[512]; 
    if (!uaArg || MSVCRT$wcslen(uaArg) == 0) {
        convertToWideChar(DEFAULT_USER_AGENT, wDefaultUA, 512);
        uaArg = wDefaultUA;
    }

    if (MyWcsICmp(cmd, L"finger") == 0) {
        doFinger(urlArg, uaArg);
    } else if (MyWcsICmp(cmd, L"print") == 0) {
        doPrint(urlArg, uaArg);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Unknown command: %ls", cmd);
    }
}
