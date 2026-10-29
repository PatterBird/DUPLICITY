#include "Session.h"
#include "./reporting/sharedHeaders/shutdown.h"
#include "./providers/processStartTerminations/ProcStartLog.h"
#include "./Microsoft.O365.Security.Krabsetw.4.4.2/lib/native/include/krabs.hpp"
#include <atomic>
#include <iostream>
#include <memory>

using namespace krabs;
static std::unique_ptr<user_trace> ETWtrace;
static std::atomic<bool> etwStarted{ false };   // Patching the race condition oops. There is still technically a small window, but thats a later problem.

void StartEtwSession(){
    OutputDebugStringW(L"[KD > ETW-0] StartEtwSession() entered\n");
    ETWtrace = std::make_unique<user_trace>(L"DUPLICITY_ETWsession");

    // Monitor for process creation
    provider<> processProvider(L"Microsoft-Windows-Kernel-Process");    // ProccessProvider and trace session must be in the same function to avoid lifetime issues.
    MonitorProcessCreate(*ETWtrace, processProvider);

    // Monitor for known registry attacks
/*   provider<> processProvider(L"Microsoft-Windows-Kernel-Registry");
    MonitorRegistry(trace, registryProvider);
*/

    // Monitor drivers
    // Compomised & vulnerable drivers have the ability to disable kernel tracing. This feature logs drivers, so if kernel events are halted mid session a log file can point to possible suspects. 
/*  provider<> processProvider(L"Microsoft-Windows-Kernel-PnP");
    MonitorDrivers(trace, registryProvider);
*/

    if (!running){
        ETWtrace.reset();
        std::cout << "[DEBUG] Shutdown requested before ETW could start!\n";
        return;
    }
    OutputDebugStringW(L"[KD > ETW-1] Running check passed\n");

    // Starts the ETW session
    //std::cout << "[DEBUG] Calling ETWtrace.start()\n";
    etwStarted = true;
    OutputDebugStringW(L"[KD > ETW-2] etwStarted set to TRUE, calling start()\n");
    ETWtrace->start();
    etwStarted = false;
    OutputDebugStringW(L"[KD > ETW-3] ETWtrace.start() returned\n");
    //std::cout << "[DEBUG] PID " << GetCurrentProcessId() << " ETWtrace.start() returned\n";
}

void stopETWSession(){
    OutputDebugStringW(L"[KD > ETW-4] stopETWSession entered\n");
    if (etwStarted && ETWtrace) {
        OutputDebugStringW(L"[KD ETW-5] Calling ETWtrace.stop()\n");
        ETWtrace->stop();
    }
}