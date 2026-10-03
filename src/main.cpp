// THIS PROJECT MUST BE RAN AS AN ADMINISTRATOR OR NT-SYSTEM ### FAILURE TO DO SO WILL RESULT IN ERROR //

// TODO: FIX TIMESTAMPS FOR EVENTS

#include "./reporting/queue.h"
#include "./reporting/sharedHeaders/shutdown.h"
#include "./Session.h"
#include "./extended/extended.h"
#include "./antiAttackerAttempts/antiRTthoughts.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <windows.h>

void extendedScan();

// DUPLICITY is verbose by default
int verbose = 1;

int main(int argc, char *argv[]){
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"Global\\FSB_spyware_2026");
    DWORD mutexError = GetLastError();

    // Handle backup relaunches from interfearing with the program
    if (hMutex == NULL) {
        std::cerr << "[!] Failed to create application mutex. Error: " << mutexError << '\n';
        return 1;
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        std::cout << "[!] DUPLICITY is already running.\n";
        CloseHandle(hMutex);
        return 0;
    }

    SetConsoleCtrlHandler(termKill, TRUE);
    int mode = 0;
    std::thread etwThread;
    std::thread extThread;
    std::thread alertThread;

    // Welcome Info
    std::cout << "#########################################################" << std::endl;
    std::cout << "############### STARTING DUPLICITY [BETA] ###############" << std::endl;
    std::cout << "#########################################################" << std::endl;
    std::cout << "      To see a list of features, use the -h flag\n" << std::endl;

    // CMDline flag parser
    int i = 1;
    while (i < argc) {

        std::string flag = argv[i];

        if (flag == "-e" || flag == "--extended") {
            mode = 1;
        }else if (flag == "-h" || flag == "--help") {
            std::cout << "[?] Usage: duplicity.exe [options]" << std::endl;
            std::cout << "  [+] Options:" << std::endl;
            std::cout << "  -e, --extended \tEnables extended monitoring outside of ETW." << std::endl;
            std::cout << "  -f, --file \t\tSpecify the file to log the results to." << std::endl;  // ToDo: Implement
            std::cout << "  -h, --help \t\tDisplays the help page." << std::endl;
            std::cout << "  -nv, --no-verbose \tDisables verbose alerts. Verbosity is enabled by default." << std::endl;  // ToDo: Implement
            std::cout << "\n" << std::endl;
            return 0;
        }else if (flag == "-nv" || flag == "--no-verbose") {
            verbose = 0;
            std::cout << "[!] Verbose flagging is disabled." << std::endl;
            std::cout << "\n" << std::endl;
        }else if (flag == "-f" || flag == "--file") {
            verbose = 0;
            std::cout << "[!] Logging output to..." << std::endl;
            std::cout << "\n" << std::endl;
        }else {
            std::cout << "[!] Unknown flag :(" << std::endl;
            std::cout << "\n" << std::endl;
            return 0;
        }
        i++;
    }

    // OS name
    osCheck();

    // Start antiRT behavior
    //goAwayRT();

    // Start the ETW session with threading
    etwThread = std::thread(StartEtwSession);
    alertThread = std::thread(alertWorker);

    // Start extended features with threading
    if (mode == 1){
        extThread = std::thread(extendedScan);
    }

    while (running){
        std::this_thread::sleep_for(
            std::chrono::milliseconds(500)
        );
    }

    // Handle shutdown signal
    cleanKill();

    // Join threads before killing!
    if (alertThread.joinable()) { alertThread.join(); }
    if (extThread.joinable()) { extThread.join(); }
    if (etwThread.joinable()) { etwThread.join(); }
    CloseHandle(hMutex);

    return 0;
}

void extendedScan() {
    while (running) {
        std::cout << "\n########## BEGINING EXTENDED SYSTEM SCAN [BETA] ########## " << std::endl;
        std::cout << "\n     This scan will run automatically every 7 min \n" << std::endl;

        SYSTEMTIME st;
        GetLocalTime(&st);

        std::wcout << L"\t#### Scan Time: " << st.wYear << L"/" << st.wMonth << L"/" << st.wDay << L" " << st.wHour << L":" << st.wMinute << L":" << st.wSecond << " ####\n" << std::endl;

        std::cout << "[?] Registry Check\n" << std::endl;
        regScan();
        std::cout << "\n[?] User Audit Check\n" << std::endl;
        userAudit();
        std::cout << "\n[?] Task Scheduler Check\n" << std::endl;
        // ??
        std::cout << "\n[?] Event Viewer\n" << std::endl;
        // ??
        std::cout << "\n[?] Open Ports\n" << std::endl;
        // ??
        std::cout << "\nCHECKS COMPLETED - Review results and resolve potentialy problamatic entries if found\n" << std::endl;
        // Save results to file

        for (int i = 0; i < 420 && running; i++){
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}
