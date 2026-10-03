// Used to help keep RT from killing the process easily.
// If you are RT and are reading this, please do not insta kill the program because that is boring.
// Also, shoutout to RT as some of these mecahnisims came from things i've seen them do to maintain persistence.

#include "antiRTthoughts.h"
#include "../reporting/queue.h"
#include "../reporting/winbox.h"
#include "../reporting/sharedHeaders/shutdown.h"
#include "../Session.h"
#include <windows.h>
#include <iostream>

BOOL WINAPI termKill(DWORD signal){
    switch (signal){
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        running = false;
        return TRUE;
    }
    return FALSE;
}

// If the program is terminated this function cleans up DUPLICITY correctly.
void cleanKill() {
    std::cout << "[DEBUG] Stopping alerting\n";
	haltAlertWorker();
    std::cout << "[DEBUG] Stopping ETW\n";
    stopETWSession();
    std::cout << "[DEBUG] Showing termination notice\n";
    noticeTermination();
    std::cout << "[DEBUG] cleanKill() finished\n";
}

void winService() {

}

void daclProcess() {

}

void registryPersist1() {
    wchar_t path[MAX_PATH];

    // Passing NULL retrieves the path of the current executable
    DWORD length = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (length == 0) {
        std::cerr << "Failed find DUPLICITY's process path" << std::endl;
		//goto defendError;
    }
}

void registryPersist2() {
	// reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe,C:\Windows\System32\wbem\Duplicity.exe" /f
}

void taskCheck() {
	//schtasks /create /tn "WinTelemetryRecovery" /tr "C:\Windows\System32\wbem\YourTelemetry.exe" /sc ONEVENT /EC Application /MO "*[System[Provider[@Name='Application Error'] and EventID=1000]]" /ru "NT AUTHORITY\SYSTEM"
}

void goAwayRT() {
	// limited to usermode, but we shall find a way to persist or terminate trying
	winService();
	daclProcess();
	registryPersist1();
	registryPersist2();
	taskCheck();
}