#include "./extended.h"
#include "../reporting/sharedHeaders/shutdown.h"
#include "../reporting/sharedHeaders/safeWrite.h"
#include <windows.h>
#include <iostream>
#include <chrono>
#include <thread>

BOOL delay = TRUE;

void startupDelay() {
    std::this_thread::sleep_for(std::chrono::seconds(35));     // Start is delayed to give the computer a sec to lock in
}

void MSDefend() {
    while (running) {
        if (delay) { startupDelay(); }
        SYSTEMTIME st;
        wchar_t command[] = L"cmd.exe /C \"\"%ProgramFiles%\\Windows Defender\\MpCmdRun.exe\" -Scan -ScanType 1 > NUL 2>&1\"";

        STARTUPINFOW startInfo = { sizeof(startInfo) };
        PROCESS_INFORMATION procInfo;

        // Create the process
        if (CreateProcessW(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startInfo, &procInfo)) {
            // Wait for the scan to finish
            WaitForSingleObject(procInfo.hProcess, INFINITE);

            DWORD exitCode;
            GetExitCodeProcess(procInfo.hProcess, &exitCode);

            std::lock_guard<std::mutex> lock(cmdMutex);
            if (exitCode == 0) {
                GetLocalTime(&st);
                std::cout << "###############################################################" << std::endl;
                std::wcout << L"[!] Quick Defender scan completed at: " << st.wYear << L"/" << st.wMonth << L"/" << st.wDay << L" " << st.wHour << L":" << st.wMinute << L":" << st.wSecond << std::endl;
                std::cout << "###############################################################" << std::endl;
            }
            else {
                std::cout << "###############################################################" << std::endl;
                std::wcout << L"[?] Defender requires user action. Exit code: " << exitCode << L"\n";
                std::cout << "###############################################################" << std::endl;

            }


            // Clean up
            CloseHandle(procInfo.hProcess);
            CloseHandle(procInfo.hThread);
        }
        else {
            std::lock_guard<std::mutex> lock(cmdMutex);
            std::cout << "###############################################################" << std::endl;
            std::cout << "[!] Quick Defender scan failed to start. Error: " << GetLastError() << std::endl;
            std::cout << "###############################################################" << std::endl;
        }

        delay = FALSE;

        for (int i = 0; i < 900 && running; i++) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}