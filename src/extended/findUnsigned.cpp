#include "extended.h"
#include "../reporting/sharedHeaders/safeWrite.h"
#include "../reporting/queue.h"
#include <Windows.h>
#include <iostream>
#include "tlhelp32.h"
#include <wintrust.h>
#include <Softpub.h>
#include <string>
#pragma comment(lib, "wintrust.lib")

BOOL foundExe = FALSE;

// Pareses running programs for unsigned applications
// https://learn.microsoft.com/en-us/windows/win32/procthread/process-enumeration
// https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file
BOOL verifySignature(LPCWSTR progPath);

void findUnsigned() {
    HANDLE hProcessList;
    PROCESSENTRY32 pe32;

    // Take a snapshot of all processes currently in the system
    hProcessList = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessList == INVALID_HANDLE_VALUE) {
        std::wcout << L"[DEBUG] Failed to take snapshot of processes." << std::endl;
        return;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information
    if (!Process32First(hProcessList, &pe32)) {
        std::wcout << L"[DEBUG] Failed to retrieve information about the first process.\n" << std::endl;
        CloseHandle(hProcessList);
        return;
    }

    do {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
        if (hProcess == NULL) { continue; }
        WCHAR path[8192];
        DWORD pathSize = 8192;
        if (!QueryFullProcessImageNameW(hProcess, 0, path, &pathSize)) { 
            CloseHandle(hProcess); 
            continue; 
        }
        CloseHandle(hProcess);
        std::wstring filePath = std::wstring(path, pathSize);

        if (filePath.empty()) { continue; }

        if (!verifySignature(filePath.c_str())) {
            foundExe = TRUE;
            SYSTEMTIME st;
            GetLocalTime(&st);

            std::wcout << L"[!] Untrusted Process" << std::endl;
            std::wcout << L"\t[-] Time Discovered: " << st.wYear << L"/" << st.wMonth << L"/" << st.wDay << L" " << st.wHour << L":" << st.wMinute << L":" << st.wSecond << std::endl;
            std::wcout << L"\t[-] PID: " << pe32.th32ProcessID << std::endl;
            std::wcout << L"\t[-] ParentPID: " << pe32.th32ParentProcessID << std::endl;
            std::wcout << L"\t[-] Process Name: " << pe32.szExeFile << std::endl;
            std::wcout << L"\t[-] Process Path: " << path << std::endl;
        }
    } while (Process32Next(hProcessList, &pe32));

    CloseHandle(hProcessList);
    if (!foundExe) { std::wcout << L"\t[!] No untrusted executables are currently running.\n" << std::endl; }
    return;
}

BOOL verifySignature(LPCWSTR progPath) {
    if (progPath == nullptr || progPath[0] == L'\0') {return FALSE;}

    WINTRUST_FILE_INFO fileCheck = {};
    fileCheck.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileCheck.pcwszFilePath = progPath;
    fileCheck.hFile = NULL;
    fileCheck.pgKnownSubject = NULL;

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA WinTrustData = {};
    WinTrustData.cbStruct = sizeof(WINTRUST_DATA);
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.pFile = &fileCheck;
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WinTrustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
    WinTrustData.dwUIContext = WTD_UICONTEXT_EXECUTE;

    LONG result = WinVerifyTrust( NULL, &WVTPolicyGUID, &WinTrustData);

    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    // search catalog for flagged files.

    return (result == ERROR_SUCCESS);
}