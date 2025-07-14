#pragma once
#include <windows.h>
#include <lm.h>

typedef DWORD NET_API_STATUS;

WINBASEAPI LPSTR WINAPI KERNEL32$lstrcpynA(LPSTR lpString1, LPCSTR lpString2, int iMaxLength);
DECLSPEC_IMPORT int WINAPI SHLWAPI$StrToIntA(LPCSTR pszSrc);
DECLSPEC_IMPORT int WINSOCK_API_LINKAGE WS2_32$WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData);
DECLSPEC_IMPORT int WINSOCK_API_LINKAGE WS2_32$getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA *pHints, PADDRINFOA *ppResult);
DECLSPEC_IMPORT SOCKET WINSOCK_API_LINKAGE WS2_32$socket(int af, int type, int protocol);
DECLSPEC_IMPORT void WINSOCK_API_LINKAGE WS2_32$freeaddrinfo(PADDRINFOA pAddrInfo);
DECLSPEC_IMPORT u_short WINSOCK_API_LINKAGE WS2_32$htons(u_short hostshort);
DECLSPEC_IMPORT int WINSOCK_API_LINKAGE WS2_32$setsockopt(SOCKET s, int level, int optname, const char *optval, int optlen);
DECLSPEC_IMPORT int WINSOCK_API_LINKAGE WS2_32$connect(SOCKET s, const struct sockaddr *name, int namelen);
DECLSPEC_IMPORT int WINSOCK_API_LINKAGE WS2_32$closesocket(SOCKET s);
DECLSPEC_IMPORT int WINSOCK_API_LINKAGE WS2_32$send(SOCKET s, const char *buf, int len, int flags);
DECLSPEC_IMPORT int WINSOCK_API_LINKAGE WS2_32$recv(SOCKET s, char *buf, int len, int flags);
DECLSPEC_IMPORT int WINSOCK_API_LINKAGE WS2_32$WSACleanup(void);
DECLSPEC_IMPORT int WINUSERAPI USER32$wsprintfA(LPSTR, LPCSTR, ...);
WINBASEAPI DWORD WINAPI KERNEL32$GetTickCount(void);
WINBASEAPI VOID WINAPI KERNEL32$RtlZeroMemory(PVOID Destination, SIZE_T Length);
WINBASEAPI VOID WINAPI KERNEL32$RtlMoveMemory(PVOID Destination, const VOID *Source, SIZE_T Length);
DECLSPEC_IMPORT ULONG NTAPI NTDLL$RtlRandomEx(PULONG Seed);
DECLSPEC_IMPORT int    WINSOCK_API_LINKAGE WS2_32$ioctlsocket(SOCKET s, long cmd, u_long *argp);
DECLSPEC_IMPORT int    WINSOCK_API_LINKAGE WS2_32$select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timeval *timeout);
DECLSPEC_IMPORT int    WINSOCK_API_LINKAGE WS2_32$getsockopt(SOCKET s, int level, int optname, char *optval, int *optlen);
DECLSPEC_IMPORT int WINSOCK_API_LINKAGE WS2_32$ioctlsocket(SOCKET s, long cmd, u_long *argp);



#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shlwapi.lib")
