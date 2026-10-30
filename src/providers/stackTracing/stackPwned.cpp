#include "../../Microsoft.O365.Security.Krabsetw.4.4.2/lib/native/include/krabs.hpp"
#include <iostream>
#include "stackPwned.h"
#include "../../reporting/winbox.h"
#include "../../reporting/sharedHeaders/safeWrite.h"

using namespace krabs;  // Wrapper for handling ETW

void ProcessMicrosoftStackThread(const EVENT_RECORD& record, const trace_context& trace_context) {

    krabs::schema schema(record, trace_context.schema_locator);
    krabs::parser parser(schema);

    SYSTEMTIME st;
    GetLocalTime(&st);

    if (schema.event_id() == 3) {
        auto processId = parser.parse<uint32_t>(L"ProcessID");
        auto threadId = parser.parse<uint32_t>(L"ThreadID");
        auto startAddr = parser.parse<uint64_t>(L"Win32StartAddr");
        bool executable = FALSE;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
        if (!hProcess) { return; }

        MEMORY_BASIC_INFORMATION mbi{};

        if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(startAddr), &mbi, sizeof(mbi))) {
            DWORD protection = mbi.Protect & 0xFF;

            bool isExecutable = (protection == PAGE_EXECUTE || protection == PAGE_EXECUTE_READ || protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY);

            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && isExecutable) {
                std::lock_guard<std::mutex> lock(cmdMutex);

                std::wcout << L"[!] ETW EVENT: " << (wchar_t*)schema.task_name() << std::endl;
                std::wcout << L"[+] Suspicious thread start address\n";
                std::wcout << L"\t[-] Time: " << st.wYear << L"/" << st.wMonth << L"/" << st.wDay << L" " << st.wHour << L":" << st.wMinute << L":" << st.wSecond << std::endl;
                std::wcout << L"\t[-] PPID: " << processId << L"\n";
                std::wcout << L"\t[-] TID: " << threadId << L"\n";
                std::wcout << L"\t[-] Address: 0x" << std::hex << startAddr << std::dec << L"\n";
                std::wcout << L"\t[-] Memory Type: MEM_PRIVATE\n";
            }
        }
        CloseHandle(hProcess);
    }
}

void MonitorStackSmash(krabs::user_trace& trace, krabs::provider<>& provider) {
    //provider.any(0x20);     // WINEVENT_KEYWORDS

    provider.add_on_event_callback([](const EVENT_RECORD& record, const trace_context& trace_context) {
        ProcessMicrosoftStackThread(record, trace_context);
        });
}