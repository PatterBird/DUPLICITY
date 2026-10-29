#include "Windows.h"
#include <iostream>
#include "./extended.h"
#include "../reporting/sharedHeaders/detRes.h"
#include "../reporting/sharedHeaders/safeWrite.h"

const std::vector<std::wstring> securityServices = {
    L"WinDefend",
    L"SecurityHealthService",
    L"wscsvc",
    L"mpssvc",
    L"BFE"
};
const std::vector<std::wstring> defenderDrivers = {
    L"WdFilter",
    L"WdBoot"
};

DetectionResult defenderServiceCheck() {
    bool suspicious = false;
    std::wstring trigger;
    std::vector<std::wstring> details;

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);

    if (!scm) {
        details.push_back(L"Unable to open Service Control Manager: " + GetLastError());
        return {false, "Defender Services", "Unable to inspect security services.", L"", details, "Service Control Manager"};
    }

    for (const auto& serviceName : securityServices) {
        SC_HANDLE service = OpenServiceW(scm, serviceName.c_str(), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);

        if (!service) {
            DWORD error = GetLastError();

            if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
                suspicious = true;

                if (trigger.empty()) { trigger = serviceName; }

                details.push_back(serviceName + L": Vital security service missing.");
            } else {
                details.push_back(serviceName + L": Unable to open service");
            }
            continue;
        }

        SERVICE_STATUS_PROCESS status{};
        DWORD bytesNeeded = 0;

        if (QueryServiceStatusEx( service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded)) {
            if (status.dwCurrentState == SERVICE_STOPPED && (serviceName == L"WinDefend" || serviceName == L"mpssvc" || serviceName == L"BFE")) {
                suspicious = true;

                if (trigger.empty()){ trigger = serviceName; }
                
                details.push_back(serviceName + L": Vital security service stopped.");
            }
        }else {
            details.push_back(serviceName + L": Unable to query service's status");
        }

        DWORD configSize = 0;
        QueryServiceConfigW(service, nullptr, 0, &configSize);

        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && configSize > 0) {
            std::vector<BYTE> buffer(configSize);

            auto config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buffer.data());

            if (QueryServiceConfigW(service, config, configSize, &configSize)) {
                if (config->dwStartType == SERVICE_DISABLED) {
                    suspicious = true;

                    if (trigger.empty()){ trigger = serviceName; }

                    details.push_back(serviceName + L": Security service disabled.");
                }
            } else { details.push_back(serviceName + L": Unable to query configuration");}
        } else {details.push_back(serviceName + L": Unable to determine configuration size");}
        CloseServiceHandle(service);
    }
    CloseServiceHandle(scm);

    return {
        suspicious, 
        "Defender Services",
        suspicious ? "Security service is possibly tampered." : "No security service tampering detected.",
        trigger,
        details,
        "Service Control Manager"
    };
}

DetectionResult defenderDriverCheck() {
    // ToDo
}