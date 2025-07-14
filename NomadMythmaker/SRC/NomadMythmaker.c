#ifdef _WIN64
// Minimal stub for stack-probing if the compiler inserts ___chkstk_ms
__declspec(naked) void ___chkstk_ms(void)
{
    __asm__("ret");
}
#endif

#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "beacon.h"
#include "NomadMythmaker.h"

#define MAX_SCRIPT_LEN 128
#define MAX_IPS 1024

// Scan statistics
typedef struct {
    int   totalScanned;
    int   totalOpen;
    int   totalClosed;
    int   timeout;
    ULONG randSeed;
} ScanStats;

static char domainFrontBuf[128] = "front.example.com"; // Default fronting domain
static char *domainFrontPtr     = domainFrontBuf;

// User Agents
const char* user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/7.68.0",
    "Wget/1.20.3 (linux-gnu)",
    "python-requests/2.25.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.97 Safari/537.36",
};
const char* http_methods[] = { "GET", "HEAD", "OPTIONS" };

// Helpers
size_t MyStrLenA(const char* str) {
    size_t len = 0;
    if (!str) return 0;
    while (str[len]) len++;
    return len;
}

void MyStrCopyA(char* dest, const char* src, size_t max) {
    if (!dest || !src || max == 0) return;
    size_t i = 0;
    while (i + 1 < max && src[i]) { dest[i] = src[i]; i++; }
    dest[i] = '\0';
}

char* MyStrChrA(const char* str, char c) {
    if (!str) return NULL;
    while (*str) { if (*str == c) return (char*)str; str++; }
    return NULL;
}

ULONG MyRandom(ULONG* seed) {
    return NTDLL$RtlRandomEx(seed);
}

void DWORDToString(DWORD value, char* buffer, size_t bufferSize) {
    if (!buffer || bufferSize == 0) return;
    char tmp[16]; int i = 0;
    if (value == 0) { buffer[0] = '0'; buffer[1] = '\0'; return; }
    while (value > 0 && i < 15) { tmp[i++] = '0' + (value % 10); value /= 10; }
    int j = 0;
    while (i > 0 && j + 1 < (int)bufferSize) { buffer[j++] = tmp[--i]; }
    buffer[j] = '\0';
}

// Custom integer parsing function
int MyStrToInt(const char* str) {
    if (!str) return 0;
    int result = 0;
    while (*str >= '0' && *str <= '9') {
        result = result * 10 + (*str - '0');
        str++;
    }
    return result;
}

// Convert IP string to 32-bit integer
DWORD IPStringToInt(const char* ip) {
    if (!ip) return 0;
    
    int octets[4] = {0, 0, 0, 0};
    int octetIndex = 0;
    int currentNum = 0;
    const char* ptr = ip;
    
    while (*ptr && octetIndex < 4) {
        if (*ptr >= '0' && *ptr <= '9') {
            currentNum = currentNum * 10 + (*ptr - '0');
        } else if (*ptr == '.') {
            if (currentNum > 255) return 0;
            octets[octetIndex] = currentNum;
            octetIndex++;
            currentNum = 0;
        } else {
            return 0; // Invalid character
        }
        ptr++;
    }
    
    // Handle the last octet
    if (currentNum > 255) return 0;
    octets[octetIndex] = currentNum;
    octetIndex++;
    
    if (octetIndex != 4) return 0;
    
    return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
}

// Convert 32-bit integer to IP string
void IPIntToString(DWORD ip, char* buffer, size_t bufferSize) {
    if (!buffer || bufferSize < 16) return;
    USER32$wsprintfA(buffer, "%d.%d.%d.%d", 
        (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

// Parse CIDR notation (e.g., 192.168.1.0/24)
BOOL ParseCIDR(const char* cidr, DWORD* network, DWORD* mask) {
    if (!cidr || !network || !mask) return FALSE;
    
    // Find the slash
    const char* slash = MyStrChrA(cidr, '/');
    if (!slash) return FALSE;
    
    // Extract IP part
    char ipStr[16];
    int ipLen = slash - cidr;
    if (ipLen >= 16 || ipLen <= 0) return FALSE;
    
    int i = 0;
    while (i < ipLen) {
        ipStr[i] = cidr[i];
        i++;
    }
    ipStr[i] = '\0';
    
    // Parse IP
    *network = IPStringToInt(ipStr);
    if (*network == 0) return FALSE;
    
    // Parse subnet mask
    int prefixLen = MyStrToInt(slash + 1);
    if (prefixLen < 0 || prefixLen > 32) return FALSE;
    
    *mask = (prefixLen == 0) ? 0 : (0xFFFFFFFF << (32 - prefixLen));
    *network = *network & *mask;
    
    return TRUE;
}

// Parse IP range (e.g., 192.168.1.10-192.168.1.20)
BOOL ParseIPRange(const char* range, DWORD* startIP, DWORD* endIP) {
    if (!range || !startIP || !endIP) return FALSE;
    
    // Find the dash
    const char* dash = MyStrChrA(range, '-');
    if (!dash) return FALSE;
    
    // Extract start IP
    char startStr[16];
    int startLen = dash - range;
    if (startLen >= 16 || startLen <= 0) return FALSE;
    
    int i = 0;
    while (i < startLen) {
        startStr[i] = range[i];
        i++;
    }
    startStr[i] = '\0';
    
    // Extract end IP (everything after the dash)
    const char* endStr = dash + 1;
    
    *startIP = IPStringToInt(startStr);
    *endIP = IPStringToInt(endStr);
    
    return (*startIP != 0 && *endIP != 0 && *startIP <= *endIP);
}

// Generate list of IPs from CIDR
int GenerateIPsFromCIDR(const char* cidr, char ipList[][16], int maxIPs) {
    DWORD network, mask;
    if (!ParseCIDR(cidr, &network, &mask)) return 0;
    
    DWORD hostMask = ~mask;
    
    // Skip network and broadcast addresses for subnets smaller than /31
    DWORD startHost = (hostMask > 1) ? 1 : 0;
    DWORD endHost = (hostMask > 1) ? hostMask - 1 : hostMask;
    
    int count = 0;
    DWORD host = startHost;
    while (host <= endHost && count < maxIPs) {
        DWORD ip = network | host;
        IPIntToString(ip, ipList[count], 16);
        count++;
        host++;
    }
    
    return count;
}

// Generate list of IPs from range
int GenerateIPsFromRange(const char* range, char ipList[][16], int maxIPs) {
    DWORD startIP, endIP;
    if (!ParseIPRange(range, &startIP, &endIP)) return 0;
    
    int count = 0;
    DWORD ip = startIP;
    while (ip <= endIP && count < maxIPs) {
        IPIntToString(ip, ipList[count], 16);
        count++;
        ip++;
    }
    
    return count;
}

BOOL ParsePortRange(const char* token, int* start, int* end) {
    if (!token || !start || !end) return FALSE;
    char* dash = MyStrChrA(token, '-');
    if (dash) {
        char a[16], b[16]; size_t i = 0;
        while (token < dash && i < 15) a[i++] = *token++;
        a[i] = '\0'; token++;
        i = 0;
        while (*token && i < 15) b[i++] = *token++;
        b[i] = '\0';
        *start = SHLWAPI$StrToIntA(a);
        *end   = SHLWAPI$StrToIntA(b);
        return (*start > 0 && *end >= *start && *end <= 65535);
    }
    *start = *end = SHLWAPI$StrToIntA(token);
    return (*start > 0 && *start <= 65535);
}

char* MyStrTokA(char* str, const char* delim, char** ctx) {
    if (!ctx) return NULL;
    if (!str) str = *ctx;
    if (!str) return NULL;
    while (*str && MyStrChrA(delim, *str)) str++;
    if (!*str) { *ctx = str; return NULL; }
    char* tok = str;
    while (*str && !MyStrChrA(delim, *str)) str++;
    if (*str) { *str = '\0'; *ctx = str + 1; }
    else { *ctx = str; }
    return tok;
}

int InitWSAContext() {
    WSADATA w;
    return WS2_32$WSAStartup(MAKEWORD(2,2), &w);
}

BOOL IsAlive(formatp* fmt, const char* ip, DWORD port, ScanStats* stats) {
    struct addrinfo  hints = {0}, *res = NULL;
    SOCKET            s    = INVALID_SOCKET;
    char              portStr[8];
    u_long            nonblock = 1, blocking = 0;
    fd_set            wfds;
    struct timeval    tv;
    int               rv, so_error = 0;
    int               errlen   = sizeof(so_error);

    // 1) Resolve target address
    KERNEL32$RtlZeroMemory(&hints, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    DWORDToString(port, portStr, sizeof(portStr));
    if (WS2_32$getaddrinfo(ip, portStr, &hints, &res) != 0) {
        return FALSE;
    }

    // 2) Create socket
    s = WS2_32$socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        WS2_32$freeaddrinfo(res);
        return FALSE;
    }

    // 3) Non‐blocking connect
    WS2_32$ioctlsocket(s, FIONBIO, &nonblock);
    WS2_32$connect(s, res->ai_addr, (int)res->ai_addrlen);

    // 4) Wait up to stats->timeout ms for the SYN‐ACK (writability)
    FD_ZERO(&wfds);
    FD_SET(s, &wfds);
    tv.tv_sec  = stats->timeout / 1000;
    tv.tv_usec = (stats->timeout % 1000) * 1000;
    rv = WS2_32$select(0, NULL, &wfds, NULL, &tv);

    // 5) If writable, check SO_ERROR to confirm connect succeeded
    if (rv > 0 &&
        WS2_32$getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&so_error, &errlen) == 0 &&
        so_error == 0)
    {
        // Port is open!
        BeaconFormatPrintf(fmt, "[+] %s:%lu is open\n", ip, port);

        // 6) Switch back to blocking so send/recv obey timeouts
        WS2_32$ioctlsocket(s, FIONBIO, &blocking);

        // 7) Apply recv timeout for banner grab
        WS2_32$setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&stats->timeout, sizeof(stats->timeout));

        // 8) Send HTTP request
        int mi = MyRandom(&stats->randSeed) % (sizeof(http_methods)/sizeof(http_methods[0]));
        int ui = MyRandom(&stats->randSeed) % (sizeof(user_agents)/sizeof(user_agents[0]));
        const char* method = http_methods[mi];
        const char* ua     = user_agents[ui];
        char req[512];
        USER32$wsprintfA(req,
            "%s / HTTP/1.0\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Connection: close\r\n"
            "\r\n",
            method, domainFrontPtr, ua
        );
        WS2_32$send(s, req, (int)MyStrLenA(req), 0);

        // 9) Read banner
        char banner[256];
        int got = WS2_32$recv(s, banner, sizeof(banner)-1, 0);
        if (got > 0) {
            banner[got] = '\0';
            BeaconFormatPrintf(fmt, "    [*] HTTP Response: %.256s\n", banner);
        }
    }

    // 10) Cleanup
    WS2_32$closesocket(s);
    WS2_32$freeaddrinfo(res);

    return (rv > 0 && so_error == 0);
}

void ScanPorts(formatp* format, const char* ip, const char* portList, ScanStats* stats) {
    char buf[256]; MyStrCopyA(buf, portList, sizeof(buf));
    char* ctx = NULL;
    char* tok = MyStrTokA(buf, ",", &ctx);
    while (tok) {
        int st, ed;
        if (ParsePortRange(tok, &st, &ed)) {
            for (int p = st; p <= ed; p++) {
                stats->totalScanned++;
                if (IsAlive(format, ip, p, stats)) stats->totalOpen++;
                else                                stats->totalClosed++;
            }
        } else {
            BeaconFormatPrintf(format, "[-] Invalid port range: %s\n", tok);
        }
        tok = MyStrTokA(NULL, ",", &ctx);
    }
}

void ScanTargets(formatp* format, const char* targets, const char* portList, ScanStats* stats) {
    char ipList[MAX_IPS][16];
    int ipCount = 0;
    
    // CIDR 
    if (MyStrChrA(targets, '/')) {
        BeaconFormatPrintf(format, "[*] Parsing CIDR: %s\n", targets);
        ipCount = GenerateIPsFromCIDR(targets, ipList, MAX_IPS);
        if (ipCount == 0) {
            BeaconFormatPrintf(format, "[-] Invalid CIDR notation: %s\n", targets);
            return;
        }
        BeaconFormatPrintf(format, "[*] Generated %d IPs from CIDR\n", ipCount);
    }
    // IP range
    else if (MyStrChrA(targets, '-')) {
        BeaconFormatPrintf(format, "[*] Parsing IP range: %s\n", targets);
        ipCount = GenerateIPsFromRange(targets, ipList, MAX_IPS);
        if (ipCount == 0) {
            BeaconFormatPrintf(format, "[-] Invalid IP range: %s\n", targets);
            return;
        }
        BeaconFormatPrintf(format, "[*] Generated %d IPs from range\n", ipCount);
    }
    // Single IP
    else {
        MyStrCopyA(ipList[0], targets, 16);
        ipCount = 1;
    }
    
    for (int i = 0; i < ipCount; i++) {
        BeaconFormatPrintf(format, "\n[*] Scanning %s\n", ipList[i]);
        ScanPorts(format, ipList[i], portList, stats);
    }
}

void go(char* args, int len) {
    char tmp[MAX_SCRIPT_LEN+1];
    int cl = len < MAX_SCRIPT_LEN ? len : MAX_SCRIPT_LEN;
    KERNEL32$RtlZeroMemory(tmp, sizeof(tmp));
    KERNEL32$RtlMoveMemory(tmp, args, cl);

    char* ctx    = NULL;
    char* targetsArg = MyStrTokA(tmp, " ", &ctx);
    char* portsArg   = MyStrTokA(NULL, " ", &ctx);
    char* frontArg   = MyStrTokA(NULL, " ", &ctx);
    
    if (!targetsArg || !portsArg) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: <IP|CIDR|IP-range> <port1,port2,...> [front-host]\n");
        BeaconPrintf(CALLBACK_ERROR, "Examples:\n");
        BeaconPrintf(CALLBACK_ERROR, "  192.168.1.1 80,443,8080\n");
        BeaconPrintf(CALLBACK_ERROR, "  192.168.1.0/24 22,80,443\n");
        BeaconPrintf(CALLBACK_ERROR, "  192.168.1.10-192.168.1.20 80-90\n");
        return;
    }
    
    if (frontArg && MyStrLenA(frontArg) > 0) {
        MyStrCopyA(domainFrontBuf, frontArg, sizeof(domainFrontBuf));
        domainFrontPtr = domainFrontBuf;
    }

    ScanStats stats;
    KERNEL32$RtlZeroMemory(&stats, sizeof(stats));
    stats.timeout  = 1000;
    stats.randSeed = KERNEL32$GetTickCount();

    formatp fmt;
    BeaconFormatAlloc(&fmt, 8192);
    if (InitWSAContext() != 0) {
        BeaconPrintf(CALLBACK_ERROR, "WSAStartup failed\n");
        BeaconFormatFree(&fmt);
        return;
    }

    DWORD start = KERNEL32$GetTickCount();
    ScanTargets(&fmt, targetsArg, portsArg, &stats);
    DWORD elapsed = KERNEL32$GetTickCount() - start;

    BeaconFormatPrintf(&fmt, "\n=== Scan Summary ===\n");
    BeaconFormatPrintf(&fmt, "Total scanned: %d\n", stats.totalScanned);
    BeaconFormatPrintf(&fmt, "Open: %d\n", stats.totalOpen);
    BeaconFormatPrintf(&fmt, "Closed: %d\n", stats.totalClosed);
    BeaconFormatPrintf(&fmt, "Time: %u.%03u s\n", elapsed/1000, elapsed%1000);

    int outLen;
    char* out = BeaconFormatToString(&fmt, &outLen);
    BeaconOutput(CALLBACK_OUTPUT, out, outLen);

    BeaconFormatFree(&fmt);
    WS2_32$WSACleanup();
}
