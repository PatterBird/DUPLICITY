// THIS PROJECT MUST BE RAN AS AN ADMINISTRATOR OR NT-SYSTEM ### FAILURE TO DO SO WILL RESULT IN ERROR //

// TODO: FIX TIMESTAMPS FOR EVENTS

#include "./reporting/queue.h"
#include "./reporting/sharedHeaders/shutdown.h"
#include "./reporting/sharedHeaders/safeWrite.h"
#include "./Session.h"
#include "./extended/extended.h"
#include "./antiAttackerAttempts/antiRTthoughts.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <mutex>
#include <windows.h>

void extendedScan();

// DUPLICITY is verbose by default
int verbose = 1;
BOOL users = TRUE;

int main(int argc, char *argv[]){
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"Global\\FSB_spyware_2026");
    DWORD mutexError = GetLastError();

    // Handle backup relaunches from interfearing with the program
    if (hMutex == NULL) {
        std::cerr << "[!] Failed to create application mutex. Error: " << mutexError << '\n';
        OutputDebugStringW(L"[KD] Failed to create application mutex.");   // DbgPrint()
        return 1;
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        std::cout << "[!] DUPLICITY is already running.\n";
        CloseHandle(hMutex);
        OutputDebugStringW(L"[KD] Sucessfully closed the duplicate instance of DUPLICITY"); 
        return 0;
    }

    SetConsoleCtrlHandler(termKill, TRUE);
    int mode = 0;
    int defend = 0;

    // COM initialization
    HRESULT comTime = CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);

    // Threads
    std::thread etwThread;
    std::thread extThread;
    std::thread MSThread;
    std::thread alertThread;

    // Welcome Info
    std::cout << "#########################################################" << std::endl;
    std::cout << "############### STARTING DUPLICITY [ALPHA] ###############" << std::endl;
    std::cout << "#########################################################" << std::endl;
    std::cout << "      To see a list of features, use the -h flag\n" << std::endl;

    // CMDline flag parser
    int i = 1;
    while (i < argc) {

        std::string flag = argv[i];

        if (flag == "-d" || flag == "--defender") {
            defend = 1;
        }else if (flag == "-e" || flag == "--extended") {
            mode = 1;
        }else if (flag == "-e1" || flag == "--extended=1") {
            mode = 1;
            users = FALSE;
        }else if (flag == "-eo" || flag == "--extended-only") {
            mode = 2;
        }else if (flag == "-eo1" || flag == "--extended-only=1") {
            mode = 2;
            users = FALSE;
        }else if (flag == "-h" || flag == "--help") {
            std::cout << "[?] Usage: duplicity.exe [options]" << std::endl;
            std::cout << "  [+] Options:" << std::endl;
            std::cout << "  -d, --defender \tRuns a quick Defender scan periodically." << std::endl;
            std::cout << "  -e, --extended \tEnables extended monitoring along with ETW.\n To run the extended scan without querying users run -e1 or --extended=1" << std::endl;
            std::cout << "  -eo, --extended-only \tOnly runs the extended monitoring feature. To run the extended scan without querying users run -e01 or --extended-only=1" << std::endl;
            std::cout << "  -f, --file \t\tSpecify the file to log the results to. (Not implemented)" << std::endl;  // ToDo: Implement
            std::cout << "  -h, --help \t\tDisplays the help page." << std::endl;
            std::cout << "  -nv, --no-verbose \tDisables verbose alerts. Verbosity is enabled by default. (Not implemented)" << std::endl;  // ToDo: Implement
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

    // MS Defender
    if (defend == 1) {
        MSThread = std::thread(MSDefend);
    }

    // Start antiRT behavior
    //goAwayRT();

    // Start the ETW session with threading
    if (mode != 2) {
        etwThread = std::thread(StartEtwSession);
    }
    alertThread = std::thread(alertWorker);

    // Start extended features with threading
    if (mode == 1 || mode == 2){
        extThread = std::thread(extendedScan);
    }

    while (running){
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    // Handle shutdown signal
    cleanKill();

    // Join threads before killing!
    if (alertThread.joinable()) { alertThread.join(); }
    if (extThread.joinable()) { extThread.join(); }
    if (etwThread.joinable()) { etwThread.join(); }
    if (MSThread.joinable()) { MSThread.join(); }
    CloseHandle(hMutex);

    return 0;
}

void extendedScan() {
    while (running) {
        {
            std::lock_guard<std::mutex> lock(cmdMutex);
            std::cout << "\n########## BEGINING EXTENDED SYSTEM SCAN [BETA] ########## " << std::endl;
            std::cout << "\n     This scan will run automatically every 7 min \n" << std::endl;
            SYSTEMTIME st;
            GetLocalTime(&st);
            std::wcout << L"\t#### Scan Time: " << st.wYear << L"/" << st.wMonth << L"/" << st.wDay << L" " << st.wHour << L":" << st.wMinute << L":" << st.wSecond << " ####\n" << std::endl;
        }
       
        std::cout << "[?] Registry / Config Check\n" << std::endl;
        regScan();
        std::cout << "\n[?] User Audit Check\n" << std::endl;
        users ? userAudit() : (void)(std::cout << "\n\t[-] User Audit Skipped\n");
        std::cout << "\n[?] Task Scheduler Check\n" << std::endl;
        taskCheck();
        std::cout << "\n[?] Event Viewer\n" << std::endl;
        // ??
        std::cout << "\nCHECKS COMPLETED - Review results and resolve potentialy problamatic entries if found\n" << std::endl;
        // Save results to file

        for (int i = 0; i < 420 && running; i++){
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}
