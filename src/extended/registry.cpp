#include "extended.h"
#include "../reporting/sharedHeaders/safeWrite.h"
#include "../reporting/queue.h"
#include <Windows.h>
#include <iostream>
#include <string>

void regRunner();
BOOL isValidRunEntry(const DetectionResult& result);

DetectionResult bootPersist(REGSAM bitVer) {
    std::string viewName;

    if (bitVer == KEY_WOW64_64KEY) {
        viewName = "64-bit";
    }else if (bitVer == KEY_WOW64_32KEY) {
        viewName = "32-bit";
    }else {
        viewName = "Default";
    }

    const std::wstring keyPath = L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager";
    HKEY hKey;
    std::vector<std::wstring> details;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager", 0, KEY_READ | bitVer, &hKey) != ERROR_SUCCESS) {
        return {false, "Boot Persistence", "Failed to open registry key.", keyPath, {}};
    }

    // Get BootExecute
    wchar_t bootExecute[1024]{};
    DWORD size = sizeof(bootExecute);
    DWORD type = 0;

    bool bootOK = false;
    std::wstring bootTriggerPath;

    LONG bootResult = RegQueryValueExW(
        hKey, L"BootExecute", nullptr, &type, reinterpret_cast<LPBYTE>(bootExecute), &size);

    if (bootResult == ERROR_SUCCESS && type == REG_MULTI_SZ && size > 0) {
        bootOK = true;

        const wchar_t* current = bootExecute;

        while (*current != L'\0') {
            std::wstring value(current);

            details.push_back(L"BootExecute: " + value);

            if (value != L"autocheck autochk *") {
                bootOK = false;

                if (bootTriggerPath.empty()) {
                    bootTriggerPath = keyPath + L"\\BootExecute";
                }
            }

            current += wcslen(current) + 1;
        }
    }
    else if (bootResult == ERROR_SUCCESS && size == 0) {
        details.push_back(L"BootExecute: <empty>");
        bootOK = false;
        bootTriggerPath = keyPath + L"\\BootExecute";
    }
    else {
        details.push_back(L"BootExecute: <missing or invalid>");
        bootOK = false;
        bootTriggerPath = keyPath + L"\\BootExecute";
    }

    // Get SetupExecute
    wchar_t setupExecute[1024]{};
    size = sizeof(setupExecute);
    type = 0;

    bool setupSuspicious = false;
    std::wstring setupTriggerPath;

    LONG setupResult = RegQueryValueExW(hKey, L"SetupExecute", nullptr, &type,  reinterpret_cast<LPBYTE>(setupExecute), &size
    );

    if (setupResult == ERROR_SUCCESS) {
        if (size == 0) {
            // Empty SetupExecute is not suspicious.
            details.push_back(L"SetupExecute: <empty>");
        } else if (type == REG_MULTI_SZ) {
            const wchar_t* current = setupExecute;
            bool hasValue = false;

            while (*current != L'\0') {
                std::wstring value(current);
                hasValue = true;

                details.push_back(L"SetupExecute: " + value);

                if (!value.empty()) {
                    setupSuspicious = true;

                    if (setupTriggerPath.empty()) {
                        setupTriggerPath = keyPath + L"\\SetupExecute";
                    }
                }

                current += wcslen(current) + 1;
            }

            if (!hasValue) {
                details.push_back(L"SetupExecute: <empty>");
            }
        } else {
            details.push_back(L"SetupExecute: <unexpected type>");
            setupSuspicious = true;
            setupTriggerPath = keyPath + L"\\SetupExecute";
        }
    } else if (setupResult == ERROR_FILE_NOT_FOUND) {
        details.push_back(L"SetupExecute: <not present>");
    } else {
        details.push_back(L"SetupExecute: <failed to read>");
        setupSuspicious = true;
        setupTriggerPath = keyPath + L"\\SetupExecute";
    }

    RegCloseKey(hKey);

    if (!bootOK) {
        return {
            true,
            "Boot Persistence",
            "BootExecute contains an unexpected configuration.",
            bootTriggerPath,
            details,
            viewName
        };
    }

    // SetupExecute contains a non-empty value
    if (setupSuspicious) {
        return {
            true,
            "Boot Persistence",
            "SetupExecute contains a non-empty configuration.",
            setupTriggerPath,
            details,
            viewName
        };
    }

    // Everything looks normal
    return {
        false,
        "Boot Persistence",
        "No suspicious evidence found.",
        L"",
        details,
        viewName
    };
}

DetectionResult ifeo(REGSAM bitVer) {
    std::string viewName;

    if (bitVer == KEY_WOW64_64KEY) {
        viewName = "64-bit";
    }
    else if (bitVer == KEY_WOW64_32KEY) {
        viewName = "32-bit";
    }
    else {
        viewName = "Default";
    }

    const std::wstring keyPath = L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    HKEY hKey;
    std::vector<std::wstring> details;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", 0, KEY_READ | bitVer, &hKey) != ERROR_SUCCESS) {
        return {false, "IFEO", "Failed to open registry key.", keyPath, {}};
    }

    bool suspicious = false;
    std::wstring triggerPath;

    DWORD index = 0;

    while (true) {
        wchar_t subKeyName[256]{};
        DWORD subKeySize = ARRAYSIZE(subKeyName);

        LONG enumResult = RegEnumKeyExW(hKey, index, subKeyName, &subKeySize, nullptr, nullptr, nullptr, nullptr);

        if (enumResult == ERROR_NO_MORE_ITEMS) {
            break;
        }

        if (enumResult != ERROR_SUCCESS) {
            index++;
            continue;
        }

        HKEY hExeKey;

        if (RegOpenKeyExW(hKey, subKeyName, 0, KEY_READ, &hExeKey) != ERROR_SUCCESS) {
            index++;
            continue;
        }

        wchar_t debugger[1024]{};
        DWORD size = sizeof(debugger);
        DWORD type = 0;

        LONG debugResult = RegQueryValueExW(hExeKey, L"Debugger", nullptr, &type, reinterpret_cast<LPBYTE>(debugger), &size);

        std::wstring exeName(subKeyName);
        std::wstring debuggerPath = keyPath + L"\\" + exeName + L"\\Debugger";

        if (debugResult == ERROR_MORE_DATA) {
            details.push_back(L"Debugger [" + exeName + L"]: value exceeds 2048 bytes");
        }else if (debugResult == ERROR_SUCCESS && size > 0 && (type == REG_SZ || type == REG_EXPAND_SZ)) {
            std::wstring value(debugger);

            if (!value.empty()) {
                suspicious = true;

                details.push_back(
                    L"Debugger [" + exeName + L"]: " + value
                );

                if (triggerPath.empty()) {
                    triggerPath = debuggerPath;
                }
            }
        }

        RegCloseKey(hExeKey);
        index++;
    }

    RegCloseKey(hKey);

    if (suspicious) {
        return {
            true,
            "IFEO",
            "IFEO Debugger value was found.",
            triggerPath,
            details,
            viewName
        };
    }

    return {
        false,
        "IFEO",
        "No IFEO Debugger values found.",
        L"",
        details,
        viewName
    };
}

DetectionResult winLogon(REGSAM bitVer) {
    std::string viewName;

    if (bitVer == KEY_WOW64_64KEY) {
        viewName = "64-bit";
    }else if (bitVer == KEY_WOW64_32KEY) {
        viewName = "32-bit";
    }else {
        viewName = "Default";
    }

}

DetectionResult lsa(REGSAM bitVer) {
    std::string viewName;

    if (bitVer == KEY_WOW64_64KEY) {
        viewName = "64-bit";
    }else if (bitVer == KEY_WOW64_32KEY) {
        viewName = "32-bit";
    }else {
        viewName = "Default";
    }

}

DetectionResult controlServices(REGSAM bitVer){
    std::string viewName;

    if (bitVer == KEY_WOW64_64KEY) {
        viewName = "64-bit";
    }else if (bitVer == KEY_WOW64_32KEY) {
        viewName = "32-bit";
    }else {
        viewName = "Default";
    }

}

DetectionResult activeSet(REGSAM bitVer) {
    std::string viewName;

    if (bitVer == KEY_WOW64_64KEY) {
        viewName = "64-bit";
    }else if (bitVer == KEY_WOW64_32KEY) {
        viewName = "32-bit";
    }else {
        viewName = "Default";
    }

}

std::vector<DetectionResult> runKeys(REGSAM bitVer, HKEY rootHive, const std::wstring& skeyPath, const std::wstring& sdisplayPath) {
    std::string viewName;

    if (bitVer == KEY_WOW64_64KEY) {
        viewName = "64-bit";
    }
    else if (bitVer == KEY_WOW64_32KEY) {
        viewName = "32-bit";
    }
    else {
        viewName = "Default";
    }

    HKEY hKey;
    std::vector<DetectionResult> detailQueued;

    LONG getResult = RegOpenKeyExW(rootHive, skeyPath.c_str(), 0, KEY_READ | bitVer, &hKey);

    if (getResult != ERROR_SUCCESS && skeyPath == L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run") {
        detailQueued.push_back({false, "RunKeys", "Explorer policies have not been created.", sdisplayPath, {}, viewName});
        return detailQueued;
    }else if (getResult != ERROR_SUCCESS) {
        detailQueued.push_back({ false, "RunKeys", "Failed to open registry key. ", sdisplayPath, {skeyPath}, viewName});
        return detailQueued;
    }

    DWORD index = 0;

    while (true) {
        DWORD type = 0;
        wchar_t valName[256]{};
        DWORD valSize = ARRAYSIZE(valName);
        wchar_t valData[256]{};
        DWORD valDataSize = sizeof(valData);

        LONG enumResult = RegEnumValueW(hKey, index, valName, &valSize, nullptr, &type, reinterpret_cast<LPBYTE>(valData), &valDataSize);

        if (enumResult == ERROR_MORE_DATA){
            std::wcout << L"Run value too large: " << std::wstring(valName) << std::endl;

            index++;
            continue;
        }

        if (enumResult == ERROR_NO_MORE_ITEMS) {
            break;
        }

        if (enumResult != ERROR_SUCCESS) {
            index++;
            continue;
        }

        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            std::wstring name(valName);
            std::wstring command(valData);

            DetectionResult result{
                true,
                "RunKeys",
                "Startup entry found",
                sdisplayPath + L"\\" + name,
                { L"Command: " + command },
                viewName
            };

            detailQueued.push_back(result);
            }
        index++;
    }

    RegCloseKey(hKey);
    return detailQueued;
}

DetectionResult defendKeys(REGSAM bitVer) {
    std::string viewName;

    if (bitVer == KEY_WOW64_64KEY) {
        viewName = "64-bit";
    }else if (bitVer == KEY_WOW64_32KEY) {
        viewName = "32-bit";
    }else {
        viewName = "Default";
    }

    //  add \Windows Advanced Threat Protection  
    int flaggedCount = 0;
    std::wstring triggerPath;
    HKEY hKey;
    std::vector<std::wstring> details;
    const std::vector<std::wstring> targetKeys =     {
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths",
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Extensions",
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Processes",
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender",
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates",
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan",

        L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
        L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions",
        L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes",
        L"SOFTWARE\\Microsoft\\Windows Defender",
        L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
        L"SOFTWARE\\Microsoft\\Windows Defender\\Features"
    };

    for (const std::wstring& relativeKey : targetKeys){
        LONG chkResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, relativeKey.c_str(), 0, KEY_READ | bitVer, &hKey);

        if (chkResult == ERROR_FILE_NOT_FOUND || chkResult == ERROR_PATH_NOT_FOUND){
            continue;
        }

        std::wstring displayPath = L"HKLM\\";
        displayPath += relativeKey;

        if (chkResult != ERROR_SUCCESS){
            return {false, "Defender", "Failed to open registry key. ", displayPath, {}};
            continue;
        }

        DWORD valueCount = 0;
        DWORD maxValueNameLength = 0;
        DWORD maxValueDataLength = 0;

        LONG infoResult = RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &valueCount, &maxValueNameLength, &maxValueDataLength, nullptr, nullptr);

        if (infoResult != ERROR_SUCCESS){
            return { false, "Defender", "Unable to enumerate values in registry key. ", displayPath, {} };
            RegCloseKey(hKey);
            continue;
        }

        for (DWORD index = 0; index < valueCount; index++){
            std::vector<wchar_t> valueName(maxValueNameLength + 1);

            std::vector<BYTE> valueData(maxValueDataLength == 0 ? 1 : maxValueDataLength);

            DWORD valueNameLength = maxValueNameLength + 1;
            DWORD valueDataLength = maxValueDataLength;
            DWORD valueType = 0;

            LONG enumResult = RegEnumValueW(hKey, index, valueName.data(), &valueNameLength, nullptr, &valueType, valueData.data(), &valueDataLength );

            if ((enumResult == ERROR_MORE_DATA) || (enumResult != ERROR_SUCCESS)){
                return { false, "Defender", "Unable to enumerate values in registry key. ", displayPath, {} };
                continue;
            }

            std::wstring fullValuePath = displayPath;
            fullValuePath += L"\\";
            fullValuePath += valueName.data();
            DWORD chkValue = 0; // Use this to check true / false values set

            if (valueType == REG_DWORD && valueDataLength >= sizeof(DWORD)){
                memcpy(&chkValue, valueData.data(), sizeof(DWORD));
            }

            std::wstring output = fullValuePath + L" [" + registryTypeName(valueType) + L"] = " + registryDataToString(valueType, valueData, valueDataLength);

            if (displayPath == L"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths"){
                details.push_back(output);
                flaggedCount++;
                if (triggerPath.empty()){triggerPath = fullValuePath;}
            }else if (displayPath == L"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Extensions") {
                details.push_back(output);
                flaggedCount++;
                if (triggerPath.empty()) {triggerPath = fullValuePath;}
            }else if (displayPath == L"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Processes") {
                details.push_back(output);
                flaggedCount++;
                if (triggerPath.empty()) {triggerPath = fullValuePath;}
            }else if (displayPath == L"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths") {
                details.push_back(output);
                flaggedCount++;
                if (triggerPath.empty()) {triggerPath = fullValuePath;}
            }else if (displayPath == L"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions") {
                details.push_back(output);
                flaggedCount++;
                if (triggerPath.empty()) {triggerPath = fullValuePath;}
            }else if (displayPath == L"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes") {
                details.push_back(output);
                flaggedCount++;
                if (triggerPath.empty()) {triggerPath = fullValuePath;}
            }else if ((fullValuePath == L"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features\\TamperProtection") && chkValue == 0) {
                details.push_back(output);
                flaggedCount++;
                if (triggerPath.empty()) { triggerPath = fullValuePath; }
            }else if ((fullValuePath == L"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\DisableAntiSpyware" || fullValuePath == L"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware") && chkValue != 0) {
                details.push_back(output);
                flaggedCount++;
                if (triggerPath.empty()) {triggerPath = fullValuePath;}
            }else if ((fullValuePath == L"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\DisableAntiVirus" || fullValuePath == L"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiVirus") && chkValue != 0) {
                details.push_back(output);
                flaggedCount++;
                if (triggerPath.empty()) {triggerPath = fullValuePath;}
            }else if ((fullValuePath == L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend\\Start" || fullValuePath == L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WdNisSvc\\Start") && chkValue == 4) {
                details.push_back(output);
                flaggedCount++;
                if (triggerPath.empty()) {triggerPath = fullValuePath;}
            }else {
                std::wcout << L"[Defender Info] " << output << std::endl;
                // flaggedCount++;
            }
        }
        RegCloseKey(hKey);
    }

    std::string summary;

    if (flaggedCount > 0){
        summary = "Flagged Defender value";
    }else{
        summary = "No Defender values flagged";
    }

    return {
        flaggedCount > 0,
        "Defender",
        summary,
        triggerPath,
        details,
        viewName
    };
}

DetectionResult xxx(REGSAM bitVer) {
    std::string viewName;

    if (bitVer == KEY_WOW64_64KEY) {
        viewName = "64-bit";
    }else if (bitVer == KEY_WOW64_32KEY) {
        viewName = "32-bit";
    }else {
        viewName = "Default";
    }

}

void reportResult(const DetectionResult& result){
    std::cout << "[" << result.name << "]\n";

    if (result.suspicious) {
        std::cout << "  [-] Version : " << result.registryView << "\n";
        std::cout << "  [-] Result: FLAGGED\n";
        std::cout << "  [-] Reason: " << result.reason << "\n";

        if (!result.triggerPath.empty()) {
            std::wcout << L"Trigger: " << result.triggerPath << L"\n";
        }

        for (const auto& detail : result.details) {
            std::wcout << detail << L"\n";
        }

        queueAlert(result);
    }
    else {
        std::cout << "  [-] Version : " << result.registryView << "\n";
        std::cout << "  [-] Result: CLEAN\n";
        std::cout << "  [-] Reason: " << result.reason << "\n";
    }
}

void regScan() {
    std::lock_guard<std::mutex> lock(cmdMutex);

    std::cout << "## Checking For Suspicious Registry Keys ##\n";

    reportResult(bootPersist(KEY_WOW64_64KEY));
    reportResult(bootPersist(KEY_WOW64_32KEY));

    reportResult(ifeo(KEY_WOW64_64KEY));
    reportResult(ifeo(KEY_WOW64_32KEY));

    regRunner();

    reportResult(defendKeys(KEY_WOW64_64KEY));
    reportResult(defendKeys(KEY_WOW64_32KEY));
}

void regRunner() {
    // wheeee
    auto runResults = runKeys(KEY_WOW64_64KEY, HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    if (runResults.empty()) {
        std::cout << "[RunKeys] No entries found in HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run (64)\n";
    }
    else {
        for (const auto& result : runResults) {
            if (isValidRunEntry(result)) {continue;}
            reportResult(result);
        }
    }
    runResults = runKeys(KEY_WOW64_32KEY, HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    if (runResults.empty()) {
        std::cout << "[RunKeys] No entries found in HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run (32)\n";
    }
    else {
        for (const auto& result : runResults) {
            if (isValidRunEntry(result)) { continue; }
            reportResult(result);
        }
    }
    // wheeee
    runResults = runKeys(KEY_WOW64_64KEY, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    if (runResults.empty()) {
        std::cout << "[RunKeys] No entries found in HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run (64)\n";
    }
    else {
        for (const auto& result : runResults) {
            if (isValidRunEntry(result)) { continue; }
            reportResult(result);
        }
    }
    runResults = runKeys(KEY_WOW64_32KEY, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    if (runResults.empty()) {
        std::cout << "[RunKeys] No entries found in HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run (32)\n";
    }
    else {
        for (const auto& result : runResults) {
            if (isValidRunEntry(result)) { continue; }
            reportResult(result);
        }
    }
    // wheeee
    runResults = runKeys(KEY_WOW64_64KEY, HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    if (runResults.empty()) {
        std::cout << "[RunKeys] No entries found in HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce (64)\n";
    }
    else {
        for (const auto& result : runResults) {
            if (isValidRunEntry(result)) { continue; }
            reportResult(result);
        }
    }
    runResults = runKeys(KEY_WOW64_32KEY, HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    if (runResults.empty()) {
        std::cout << "[RunKeys] No entries found in HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce (32)\n";
    }
    else {
        for (const auto& result : runResults) {
            if (isValidRunEntry(result)) { continue; }
            reportResult(result);
        }
    }
    // wheeee
    runResults = runKeys(KEY_WOW64_64KEY, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    if (runResults.empty()) {
        std::cout << "[RunKeys] No entries found in HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce (64)\n";
    }
    else {
        for (const auto& result : runResults) {
            if (isValidRunEntry(result)) { continue; }
            reportResult(result);
        }
    }
    runResults = runKeys(KEY_WOW64_32KEY, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    if (runResults.empty()) {
        std::cout << "[RunKeys] No entries found in HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce (32)\n";
    }
    else {
        for (const auto& result : runResults) {
            if (isValidRunEntry(result)) { continue; }
            reportResult(result);
        }
    }
    // wheeee
    runResults = runKeys(KEY_WOW64_64KEY, HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run");
    if (runResults.empty()) {
        std::cout << "[RunKeys] No entries found in HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run (64)\n";
    }
    else {
        for (const auto& result : runResults) {
            if (isValidRunEntry(result)) { continue; }
            reportResult(result);
        }
    }
    runResults = runKeys(KEY_WOW64_32KEY, HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run");
    if (runResults.empty()) {
        std::cout << "[RunKeys] No entries found in HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run (32)\n";
    }
    else {
        for (const auto& result : runResults) {
            if (isValidRunEntry(result)) { continue; }
            reportResult(result);
        }
    }
    runResults = runKeys(KEY_WOW64_64KEY, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run");
    if (runResults.empty()) {
        std::cout << "[RunKeys] No entries found in HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run (64)\n";
    }
    else {
        for (const auto& result : runResults) {
            if (isValidRunEntry(result)) { continue; }
            reportResult(result);
        }
    }
    runResults = runKeys(KEY_WOW64_32KEY, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run");
    if (runResults.empty()) {
        std::cout << "[RunKeys] No entries found HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run (32)\n";
    }
    else {
        for (const auto& result : runResults) {
            if (isValidRunEntry(result)) { continue; }
            reportResult(result);
        }
    }
    // wheeee
    runResults = runKeys(KEY_WOW64_64KEY, HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices", L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run");
    if (runResults.empty()) {
        std::cout << "[RunKeys] No entries found in HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices (64)\n";
    }
    else {
        for (const auto& result : runResults) {
            if (isValidRunEntry(result)) { continue; }
            reportResult(result);
        }
    }
    runResults = runKeys(KEY_WOW64_32KEY, HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices", L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices");
    if (runResults.empty()) {
        std::cout << "[RunKeys] No entries found in HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices (32)\n";
    }
    else {
        for (const auto& result : runResults) {
            if (isValidRunEntry(result)) { continue; }
            reportResult(result);
        }
    }
    runResults = runKeys(KEY_WOW64_64KEY, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices");
    if (runResults.empty()) {
        std::cout << "[RunKeys] No entries found in HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices (64)\n";
    }
    else {
        for (const auto& result : runResults) {
            if (isValidRunEntry(result)) { continue; }
            reportResult(result);
        }
    }
    runResults = runKeys(KEY_WOW64_32KEY, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices", L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices");
    if (runResults.empty()) {
        std::cout << "[RunKeys] No entries found HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices (32)\n";
    }
    else {
        for (const auto& result : runResults) {
            if (isValidRunEntry(result)) { continue; }
            reportResult(result);
        }
    }
}

BOOL isValidRunEntry(const DetectionResult& result) {
    for (const auto& detail : result.details){
        if (detail.find(L"%windir%\\system32\\SecurityHealthSystray.exe") != std::wstring::npos){
            return true;
        }
        else if (detail.find(L"C:\\system32\\SecurityHealthSystray.exe") != std::wstring::npos) {
            return true;
        }else if (detail.find(L"C:\\Program Files\\Netbird\\Netbird - ui.exe") != std::wstring::npos) {
           return true;
        }else if (detail.find(L"C:\\Program Files\\Netbird\\Netbird-ui.exe") != std::wstring::npos) {
            return true;
        }else if (detail.find(L"\"C:\\Program Files(x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --no-startup-window --win-session-start") != std::wstring::npos) {
            return true;
        }else if (detail.find(L"placeholder") != std::wstring::npos) {
            return true;
        }
    }
    return false;
}