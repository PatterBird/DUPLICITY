#include "../../Microsoft.O365.Security.Krabsetw.4.4.2/lib/native/include/krabs.hpp"
#include "ProcStartLog.h"
#include "../../reporting/winbox.h"
#include "../../reporting/sharedHeaders/safeWrite.h"
#include <iostream>

using namespace krabs;  // Wrapper for handling ETW

// NOTE: depending on the data type you may need to use std::cout or std:wcout for handling data!

void ProcessMicrosoftKernelProcessEvent(const EVENT_RECORD& record, const trace_context& trace_context) {

    // Schema and parser are used to read event fields
    krabs::schema schema(record, trace_context.schema_locator);
    krabs::parser parser(schema);

    SYSTEMTIME st;
    SYSTEMTIME utcst;
    GetLocalTime(&st);

    // Proc ID 1 is event creation
    // To get the ID value of specific actions use the EtwExplorer tool and navigate to the XML tab for the desired provider. EX: <event value="1" symbol="ProcessStart"...
    if (schema.event_id() == 1) {
        std::lock_guard<std::mutex> lock(cmdMutex);

        std::wcout << L"[!] ETW EVENT: " << (wchar_t*)schema.task_name() << std::endl;

        // Each value comes from the template linked to the event
        auto createprocessId = parser.parse<uint32_t>(L"ProcessID");
        auto createcreateTime = parser.parse<FILETIME>(L"CreateTime");
        auto createparentProcessId = parser.parse<uint32_t>(L"ParentProcessID");
        auto createimageName = parser.parse<std::wstring>(L"ImageName");

        // Display info to terminal
        std::cout << "[+] Process created" << std::endl;
        std::cout << "\t[-] PID: " << createprocessId << std::endl;
        std::cout << "\t[-] ParentPID: " << createparentProcessId << std::endl;

        // Standarize create time to something readable
        if ( FileTimeToSystemTime(&createcreateTime, &utcst) && SystemTimeToTzSpecificLocalTime(nullptr, &utcst, &st)){
            std::wcout << L"\t[-] Create Time: " << st.wYear << L"/" << st.wMonth << L"/" << st.wDay << L" " << st.wHour << L":" << st.wMinute << L":" << st.wSecond << std::endl;
        }

        std::wcout << "\t[-] Image Name: " << createimageName << std::endl;
        std::cout << "\n" << std::endl;

        // Log the event


    } else if (schema.event_id() == 2) {
        std::lock_guard<std::mutex> lock(cmdMutex);

        std::wcout << L"[!] ETW EVENT: " << (wchar_t*)schema.task_name() << std::endl;

        auto termprocessId = parser.parse<uint32_t>(L"ProcessID");
        auto termcreateTime = parser.parse<FILETIME>(L"CreateTime");
        auto termexitTime = parser.parse<FILETIME>(L"ExitTime");
        auto termimageName = parser.parse<std::string>(L"ImageName");

        std::cout << "[+] Process terminated" << std::endl;
        std::cout << "\t[-] PID: " << termprocessId << std::endl;
        if (FileTimeToSystemTime(&termcreateTime, &utcst) && SystemTimeToTzSpecificLocalTime(nullptr, &utcst, &st)) {
            std::wcout << L"\t[-] Create Time: " << st.wYear << L"/" << st.wMonth << L"/" << st.wDay << L" " << st.wHour << L":" << st.wMinute << L":" << st.wSecond << std::endl;
        }
        if (FileTimeToSystemTime(&termexitTime, &utcst) && SystemTimeToTzSpecificLocalTime(nullptr, &utcst, &st)) {
            std::wcout << L"\t[-] Create Time: " << st.wYear << L"/" << st.wMonth << L"/" << st.wDay << L" " << st.wHour << L":" << st.wMinute << L":" << st.wSecond << std::endl;
        }
        std::cout << "\t[-] Image Name: " << termimageName << std::endl;
        std::cout << "\n" << std::endl;
    } else if (schema.event_id() == 5 ) {
        std::lock_guard<std::mutex> lock(cmdMutex);

        auto imgimageName = parser.parse<std::wstring>(L"ImageName");
        auto imgprocessId = parser.parse<uint32_t>(L"ProcessID");
        auto imgcheckSum = parser.parse<uint32_t>(L"ImageCheckSum");
        auto imgtimedateStamp = parser.parse<uint32_t>(L"TimeDateStamp");   // gonna need to fix at some point

        // Ignore loaded images from "safe" directories to reduce noise. WIll need to be updated for more robust detection.
        if (imgimageName.find(L"\\Windows\\UUS\\") != std::wstring::npos || imgimageName.find(L"\\Windows\\System32\\") != std::wstring::npos || imgimageName.find(L"\\Windows\\SysWOW64\\") != std::wstring::npos || imgimageName.find(L"\\Windows\\WinSxS\\") != std::wstring::npos || imgimageName.find(L"\\Program Files\\WindowsApps\\") != std::wstring::npos || imgimageName.find(L"\\Windows\\SysWOW64\\") != std::wstring::npos || imgimageName.find(L"\\Windows\\WinSxS\\") != std::wstring::npos || imgimageName.find(L"\\Program Files\\Google\\Chrome") != std::wstring::npos) {
            return;
        }

        //alertXYZ();
        std::wcout << L"[!] ETW EVENT: " << (wchar_t*)schema.task_name() << std::endl;

        std::cout << "[+] Image Loaded" << std::endl;
        std::wcout << "\t[-] Image Name: " << imgimageName << std::endl;
        std::cout << "\t[-] PID: " << imgprocessId << std::endl;
        std::cout << "\t[-] Checksum: " << imgcheckSum << std::endl;
        std::cout << "\t[-] PE image timestamp: " << imgtimedateStamp << std::endl;
        std::cout << "\n" << std::endl;
    }
}

void MonitorProcessCreate(krabs::user_trace& trace, krabs::provider<>& provider)
{
    provider.any(0x10 | 0x40);     // WINEVENT_KEYWORDS

    provider.add_on_event_callback([](const EVENT_RECORD& record,const trace_context& trace_context){
            ProcessMicrosoftKernelProcessEvent(record,trace_context);
        });

    trace.enable(provider);
}