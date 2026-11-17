//Scan event viewer logs
#include "./extended.h"
#include <winevt.h>
#include "windows.h"
#include <iostream>
#include <vector>
#include <string>

#pragma comment(lib, "wevtapi.lib")

/*
104 Event Log cleared - sys
1102 Audit log was cleared - Sec
1120 Defender remediation  - MS Defender
4698 SchTask was created - Sec
4699 SchTask was deleted - Sec
4702 SchTask was updated - Sec
5025 WinFirewall stopped - Sec
4720 User created - Sec
4726 User deleted - Sec
5001 = Real Time protection disabled - MS Defender
5010, 5012 AV scanning diabled - MS Defender
7034 Service termination  - Sys
??7045 Service instalation - Sys??
*/

struct EventLogTarget {
    std::wstring channel;
    std::vector<int> eventIDs;
};

const std::vector<EventLogTarget> baseEventID = {
    {L"Security", {1102, 4698, 4720, 4726, 4699, 4702, 4782, 5025}},
    {L"System",{104, 7034}},
    {L"Microsoft-Windows-Windows Defender/Operational", {1118, 1119, 5001, 5010, 5012}}
};

void forensicFind() {
    for (const auto& target : baseEventID) {
        std::wcout << L"\n[Scanning Event Log: " << target.channel << L"]\n";
        std::wstring query = L"*[System[(";

        for (size_t i = 0; i < target.eventIDs.size(); i++) {
            if (i > 0){ query += L" or "; }

            query += L"EventID=" + std::to_wstring(target.eventIDs[i]);
        }

        query += L")]]";

        EVT_HANDLE results = EvtQuery( nullptr, target.channel.c_str(), query.c_str(), EvtQueryChannelPath | EvtQueryReverseDirection);

        if (!results) {
            std::wcout << L"\t[-] Unable to query " << target.channel << std::endl;
            continue;
        }

        DWORD total = 0;
        EVT_HANDLE events[10] = {};
        DWORD returned = 0;

        while (total < 25) {

            if (!EvtNext(results, 10, events, 0, 0, &returned)) {
                if (GetLastError() != ERROR_NO_MORE_ITEMS) { std::wcout << L"\t[-] Event read error" << std::endl; }

                break;
            }

            for (DWORD i = 0; i < returned; i++) {

                DWORD bufferSize = 0;
                DWORD propertyCount = 0;

                BOOL rendered = EvtRender(nullptr, events[i], EvtRenderEventXml, 0, nullptr, &bufferSize, &propertyCount);

                DWORD error = rendered ? ERROR_SUCCESS : GetLastError();

                if (!rendered && error == ERROR_INSUFFICIENT_BUFFER) {
                    std::vector<wchar_t> buffer((bufferSize + sizeof(wchar_t) - 1) / sizeof(wchar_t));

                    if (EvtRender(nullptr, events[i], EvtRenderEventXml, bufferSize, buffer.data(), &bufferSize, &propertyCount)) {
                        std::wcout << L"\n\t[-] Channel: " << target.channel << std::endl;
                        std::wcout << L"\t[-] Event XML: " << buffer.data() << std::endl;
                        total++;
                    }
                }
                EvtClose(events[i]);
            }
        }
        EvtClose(results);
    }
}

/*
XXXX idk
*/
void sysmonCheck() {
	// if sysmon installed, check it. Else return
	return;
}

void eventView() {
	forensicFind();
	sysmonCheck();
}