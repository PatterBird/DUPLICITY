#include "Windows.h"
#include <iostream>
#include "./extended.h"
#include "../reporting/sharedHeaders/detRes.h"
#include "../reporting/sharedHeaders/safeWrite.h"

// There are more but these are the core ones
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
        details.push_back(L"Unable to open Service Control Manager: " + std::to_wstring(GetLastError()));
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

        BOOL result = QueryServiceConfigW(service, nullptr, 0, &configSize);
        DWORD error = result ? ERROR_SUCCESS : GetLastError();

        if (!result && error == ERROR_INSUFFICIENT_BUFFER && configSize > 0) {
            std::vector<BYTE> buffer(configSize);

            auto config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buffer.data());

            if (QueryServiceConfigW(service, config, configSize, &configSize)) {
                if (config->dwStartType == SERVICE_DISABLED) {
                    suspicious = true;

                    if (trigger.empty()) { trigger = serviceName; }

                    details.push_back(serviceName + L": Security service disabled.");
                }
            }else {
                DWORD error = GetLastError();
                details.push_back(serviceName + L": Unable to query configuration. Error: " + std::to_wstring(error));
            }
        }else {details.push_back(serviceName + L": Unable to determine configuration size. Error: " + std::to_wstring(error));}
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
    bool suspicious = false;
    std::wstring trigger;
    std::vector<std::wstring> details;

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);

    if (!scm) {
        details.push_back(L"Unable to open Service Control Manager: " + std::to_wstring(GetLastError()));

        return {
            false,
            "Defender Drivers",
            "Unable to inspect Defender drivers.",
            L"",
            details,
            "SCM"
        };
    }

    for (const auto& driverName : defenderDrivers) {
        SC_HANDLE driver = OpenServiceW(scm,driverName.c_str(),SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);

        if (!driver) {

            if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
                suspicious = true;

                if (trigger.empty()){ trigger = driverName; }

                details.push_back(driverName + L": Defender driver missing.");
            }else {
                details.push_back(driverName + L": Unable to open driver: ");
            }
            continue;
        }

        SERVICE_STATUS_PROCESS status{};
        DWORD bytesNeeded = 0;

        if (QueryServiceStatusEx(driver, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded)) {
            if (status.dwCurrentState == SERVICE_STOPPED && driverName == L"WdFilter") {
                suspicious = true;

                if (trigger.empty()) { trigger = driverName; }

                details.push_back(driverName + L": Defender file-system filter driver stopped.");
            }
        }
        else {
            details.push_back(driverName + L": Unable to query driver status: ");
        }

        DWORD configSize = 0;
        BOOL result = QueryServiceConfigW(driver, nullptr, 0, &configSize);

        if (!result && GetLastError() == ERROR_INSUFFICIENT_BUFFER && configSize > 0) {
            std::vector<BYTE> buffer(configSize);

            auto config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buffer.data());

            if (QueryServiceConfigW(driver, config, configSize, &configSize)) {
                if (config->dwStartType == SERVICE_DISABLED) {
                    suspicious = true;

                    if (trigger.empty()) { trigger = driverName; }

                    details.push_back(driverName + L": Defender driver disabled.");
                }

                if (config->dwServiceType != SERVICE_KERNEL_DRIVER && config->dwServiceType != SERVICE_FILE_SYSTEM_DRIVER) {

                    suspicious = true;

                    if (trigger.empty()) { trigger = driverName; }

                    details.push_back(driverName + L": Unexpected driver service type.");
                }

                if (config->lpBinaryPathName && wcslen(config->lpBinaryPathName) > 0) {

                    std::wstring driverPath = config->lpBinaryPathName;
                    if (driverPath.rfind(L"\\SystemRoot\\", 0) == 0) { driverPath.replace(0, 11, L"%SystemRoot%\\"); }

                    // Expand environment variables such as %SystemRoot%.
                    DWORD required = ExpandEnvironmentStringsW(driverPath.c_str(), nullptr, 0);



                    if (required > 0) {
                        std::wstring expanded(required, L'\0');

                        DWORD written = ExpandEnvironmentStringsW(driverPath.c_str(), expanded.data(), required);

                        if (written > 0 && written <= required) {
                            expanded.resize(written - 1);
                            driverPath = expanded;
                        }
                    }

                    DWORD attributes = GetFileAttributesW(driverPath.c_str());

                    if (attributes == INVALID_FILE_ATTRIBUTES) {
                        DWORD error = GetLastError();

                        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {

                            suspicious = true;

                            if (trigger.empty()) { trigger = driverName; }

                            details.push_back(driverName + L": Driver file missing: " + driverPath);
                        }
                        else {
                            details.push_back(driverName + L": Unable to inspect driver file");
                        }
                    }
                }
            }
            else {
                details.push_back(
                    driverName + L": Unable to query configuration");
            }
        }
        else {
            details.push_back( driverName + L": Unable to determine configuration size");
        }
        CloseServiceHandle(driver);
    }
    CloseServiceHandle(scm);

    return {
        suspicious,
        "Defender Drivers",
        suspicious ? "Defender driver integrity findings." : "No Defender driver tampering detected.",
        trigger,
        details,
        "SCM"
    };
}
