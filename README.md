# Metasploit C Custom Reverse Shell

A minimal Windows reverse shell implementation in pure C. This repository demonstrates a low-detection reverse shell that uses dynamic loading and Windows API to establish a reverse connection.

## About

I was doing a CTF on tryhackme which required a 64 bit binary and didn't want to use nim to bypass defender. Was wondering how hard it would be to set one up. Nims default detections are: 36/73 - however notably it can still bypass defender. 
- https://github.com/Sn1r/Nim-Reverse-Shell/tree/main

<p align="center">
  <img src="https://github.com/pentestfunctions/metasploit_c_custom/blob/main/images/Metasploit_Connection.gif">
</p>

## Overview

This project contains a simple, customizable reverse TCP shell for Windows systems written in C. It's designed to be:

- Lightweight (small binary size) (65KB)
- Low detection rate (6/71 on VirusTotal as of March 2025)
- Customizable (IP and port can be defined at compile time)
- Compatible with both 32-bit and 64-bit Windows

--- 

## Usage

1. Replace `YOUR_IP_HERE` with your actual IP address
2. Compile using `gcc -O2 backdoor.c -o github_gcc_test.exe` on a windows machine
3. Set up a metasploit listener on your machine: `msfconsole -q -x "use exploit/multi/handler; set LHOST eth0; set LPORT 4444; set Payload generic/shell_reverse_tcp; run -j"`
4. Run the executable on the target Windows machine

NOTES: Change tun0 to eth0 or whatever you need for your VM environment or local network. 

---

## Technical Details

The code uses several techniques to minimize detection and maintain compatibility:

1. **Dynamic DLL Loading**: Instead of static linking to ws2_32.dll, the code loads it at runtime using LoadLibraryA, reducing suspicious import table entries.

2. **Function Pointer Resolution**: All network functions are resolved via GetProcAddress, avoiding direct imports of networking functions commonly flagged by AVs.

3. **Minimal Dependencies**: Only Windows.h is included, using WIN32_LEAN_AND_MEAN to reduce header size.

4. **No Winsock Headers**: The code manually defines all necessary Winsock structures and constants rather than including winsock2.h.

5. **Console Window Hiding**: Uses GetConsoleWindow() and ShowWindow() to hide the console window when executed.

6. **Random Delay**: Implements a small random delay before connection to potentially evade runtime behavior analysis.

7. **Reused Socket Handle**: Uses the socket as standard input/output/error for the cmd process, eliminating the need for manual data forwarding.

8. **Process Creation with Hidden Window**: Creates the command shell with CREATE_NO_WINDOW flag to prevent visible windows.

9. **Clean Resource Handling**: Properly closes handles and frees resources, helping avoid detection by resource monitoring.

## Compilation

To compile with TDM-GCC:

```bash
gcc -O2 backdoor.c -o backdoor_tdm.exe -mwindows
```

## AV Detection Comparison

The current build has 6/71 detections on VirusTotal (as of March 21, 2025) but these will increase as time goes on due to the way virustotal works:
https://www.virustotal.com/gui/file/945b20261ce44660aa6b9f4db5161cf94df11c2943f812a3e1317bc845695a95?nocache=1

- DeepInstinct: MALICIOUS
- Elastic: Malicious (high Confidence)
- Google: Detected
- Ikarus: Trojan.Win64.Reverseshell
- SecureAge: Malicious
- Symantec: ML.Attribute.HighConfidence

## Compiler Detection Influence

Even harmless Hello World programs trigger false positives with certain compiler flags:

```c
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
```

Detection rates by compiler/flags:

| Compiler Command | Detections | Notable Detectors |
|------------------|------------|-------------------|
| x86_64-w64-mingw32-gcc -o hello1.exe hello.c | 7/73 | AhnLab-V3, Elastic, Google |
| x86_64-w64-mingw32-gcc -o hello2.exe hello.c -s -Os | 3/73 | Google, Ikarus, SecureAge |
| x86_64-w64-mingw32-gcc -o hello4.exe hello.c -static | 7/73 | AhnLab-V3, Elastic, Google |
| x86_64-w64-mingw32-gcc -o hello5.exe hello.c -s -Wl,--strip-all | 4/73 | Google, Ikarus, SecureAge |

## Disclaimer

This code is provided for educational purposes only. Use only on systems you own or have permission to test. Unauthorized access to computer systems is illegal and unethical.

## License

MIT
