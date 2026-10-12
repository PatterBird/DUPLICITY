#include "extended.h"
#include "../reporting/sharedHeaders/safeWrite.h"
#include "../reporting/queue.h"
#include <Windows.h>
#include <iostream>
#include <mutex>
#include <memory>
#include <vector>

void regRunner();
BOOL isValidRunEntry(const DetectionResult& result);

// Custom anon namespace
namespace {
    // Set max size for registry data allowed to be read in
    constexpr DWORD kMaxRegistryData = 8 * 1024;
    constexpr DWORD kMaxRegistryName = 8192;

    // Close handle when done with a key to prevent handle based memory leaks
    struct KeyCloser {
        void operator()(HKEY key) const noexcept { if (key) { RegCloseKey(key); } }
    };
    using KeyHandle = std::unique_ptr<std::remove_pointer_t<HKEY>, KeyCloser>;

    std::string viewLabel(REGSAM view) {return view == KEY_WOW64_64KEY ? "64-bit" : view == KEY_WOW64_32KEY ? "32-bit" : "Default";}

    // Long form to short form
    std::wstring hiveLabel(HKEY root) {
        if (root == HKEY_LOCAL_MACHINE) { return L"HKLM"; }
        if (root == HKEY_CURRENT_USER) { return L"HKCU"; }
        if (root == HKEY_USERS) { return L"HKU"; }
        return L"HKEY";
    }

    std::wstring errorText(LONG code) { return L"[DEBUG] Win32 error: " + std::to_wstring(code); }

    // Logic for opening a key
    struct KeyOpen {
        KeyHandle key;
        LONG status = ERROR_SUCCESS;
    };
    KeyOpen openRegistryKey(HKEY root, const std::wstring& path, REGSAM view) {
        HKEY raw = nullptr;
        LONG code = RegOpenKeyExW(root, path.c_str(), 0, KEY_READ | view, &raw);
        return { KeyHandle(code == ERROR_SUCCESS ? raw : nullptr), code };
    }

    // Logic for reading a key
    struct RegistryValue {
        std::wstring name;
        std::vector<BYTE> bytes;
        DWORD type = REG_NONE;
    };
    struct ValueRead {
        RegistryValue value;
        LONG status = ERROR_SUCCESS;
    };

    ValueRead readRegistryValue(HKEY key, const std::wstring& name) {
        for (int attempt = 0; attempt < 3; ++attempt) {
            DWORD size = 0, type = REG_NONE;
            LONG code = RegQueryValueExW(key, name.c_str(), nullptr, &type, nullptr, &size);
            if (code != ERROR_SUCCESS) return { {}, code };
            if (size > kMaxRegistryData) return { {}, ERROR_MORE_DATA };
            std::vector<BYTE> bytes(std::max<DWORD>(size, 1));
            DWORD actual = static_cast<DWORD>(bytes.size());
            code = RegQueryValueExW(key, name.c_str(), nullptr, &type, bytes.data(), &actual);
            if (code == ERROR_MORE_DATA) continue;
            if (code != ERROR_SUCCESS) return { {}, code };
            if (actual > kMaxRegistryData || actual > bytes.size()) return { {}, ERROR_INVALID_DATA };
            bytes.resize(actual);
            return { {name, std::move(bytes), type}, ERROR_SUCCESS };
        }
        return { {}, ERROR_MORE_DATA };
    }

    // Key type and value validation checks
    bool registryString(const RegistryValue& entry, std::wstring& text, std::wstring& error) {
        if (entry.type != REG_SZ && entry.type != REG_EXPAND_SZ) {
            error = L"Unexpected string registry type";
            return false;
        }
        if (entry.bytes.size() < sizeof(wchar_t) || entry.bytes.size() % sizeof(wchar_t)) {
            error = L"Invalid string byte length";
            return false;
        }
        text.resize(entry.bytes.size() / sizeof(wchar_t));
        std::memcpy(text.data(), entry.bytes.data(), entry.bytes.size());
        if (text.back() != L'\0') {
            error = L"Missing null terminator";
            return false;
        }
        text.pop_back();
        if (text.find(L'\0') != std::wstring::npos) {
            error = L"Embedded or additional null characters";
            return false;
        }
        return true;
    }

    bool registryMultiString(const RegistryValue& entry, std::vector<std::wstring>& strings, std::wstring& error) {
        strings.clear();
        error.clear();

        if (entry.type != REG_MULTI_SZ) {
            error = L"Expected REG_MULTI_SZ";
            return false;
        }

        // Accept an empty REG_MULTI_SZ.
        if (entry.bytes.empty()) {
            return true;
        }

        // Registry data must contain complete wchar_t values.
        if (entry.bytes.size() % sizeof(wchar_t) != 0) {
            error = L"Invalid REG_MULTI_SZ byte length";
            return false;
        }

        std::wstring data( entry.bytes.size() / sizeof(wchar_t), L'\0');

        std::memcpy(data.data(), entry.bytes.data(), entry.bytes.size());

        // Accept empty values encoded with one or two nulls.
        if (data == L"\0" || (data.size() == 1 && data[0] == L'\0') || (data.size() == 2 && data[0] == L'\0' && data[1] == L'\0')) { return true; }

        // Nonempty REG_MULTI_SZ requires double-null termination.
            if (data.size() < 2 || data[data.size() - 1] != L'\0' || data[data.size() - 2] != L'\0') {
            error = L"REG_MULTI_SZ lacks double-null termination";
            return false;
        }

        size_t pos = 0;

        while (pos < data.size() - 1) {
            size_t end = data.find(L'\0', pos);

            if (end == std::wstring::npos) {
                error = L"Malformed REG_MULTI_SZ";
                strings.clear();
                return false;
            }

            if (end == pos) {
                if (pos != data.size() - 1) {
                    error = L"Unexpected empty or trailing data";
                    strings.clear();
                    return false;
                }
                break;
            }

            strings.push_back(data.substr(pos, end - pos));
            pos = end + 1;
        }

        return true;
    }

    // Logic for enumerating values
    struct ValueEnumeration {
        std::vector<RegistryValue> values;
        LONG status = ERROR_SUCCESS;
    };
    ValueEnumeration enumerateRegistryValues(HKEY key) {
        ValueEnumeration out;
        DWORD count = 0, maxName = 0, maxData = 0;
        out.status = RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &count, &maxName, &maxData, nullptr, nullptr);
        if (out.status != ERROR_SUCCESS) return out;
        if (maxName > kMaxRegistryName || maxData > kMaxRegistryData) {
            out.status = ERROR_MORE_DATA; return out;
        }
        for (DWORD i = 0; i < count; ++i) {
            bool done = false;
            for (int attempt = 0; attempt < 3; ++attempt) {
                std::vector<wchar_t> name(maxName + 2, L'\0');
                std::vector<BYTE> bytes(std::max<DWORD>(maxData, 1));
                DWORD nameLen = static_cast<DWORD>(name.size());
                DWORD byteLen = static_cast<DWORD>(bytes.size());
                DWORD type = REG_NONE;
                LONG code = RegEnumValueW(key, i, name.data(), &nameLen, nullptr,
                    &type, bytes.data(), &byteLen);
                if (code == ERROR_MORE_DATA) {
                    if (nameLen > kMaxRegistryName || byteLen > kMaxRegistryData) {
                        out.status = ERROR_MORE_DATA; return out;
                    }
                    maxName = (maxName + 1 > nameLen + 1) ? maxName + 1 : nameLen + 1;
                    maxData = (maxData + 1 > byteLen + 1) ? maxData + 1 : byteLen + 1;
                    continue;
                }
                if (code == ERROR_NO_MORE_ITEMS) return out;
                if (code != ERROR_SUCCESS) { out.status = code; return out; }
                if (byteLen > bytes.size() || nameLen > name.size()) {
                    out.status = ERROR_INVALID_DATA; return out;
                }
                bytes.resize(byteLen);
                out.values.push_back({ std::wstring(name.data(), nameLen), std::move(bytes), type });
                done = true;
                break;
            }
            if (!done) { out.status = ERROR_MORE_DATA; return out; }
        }
        return out;
    }

    struct SubkeyEnumeration {
        std::vector<std::wstring> names;
        LONG status = ERROR_SUCCESS;
    };
    SubkeyEnumeration enumerateSubkeys(HKEY key) {
        SubkeyEnumeration out;
        DWORD count = 0, maxLen = 0;
        out.status = RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, &count, &maxLen, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
        if (out.status != ERROR_SUCCESS) return out;
        if (maxLen > kMaxRegistryName) { out.status = ERROR_MORE_DATA; return out; }
        for (DWORD i = 0; i < count; ++i) {
            std::vector<wchar_t> buffer(maxLen + 2);
            DWORD length = static_cast<DWORD>(buffer.size());
            LONG code = RegEnumKeyExW(key, i, buffer.data(), &length, nullptr, nullptr, nullptr, nullptr);
            if (code == ERROR_NO_MORE_ITEMS) break;
            if (code != ERROR_SUCCESS) { out.status = code; return out; }
            out.names.emplace_back(buffer.data(), length);
        }
        return out;
    }

    // More error handling logic
    bool equalIgnoreCase(const std::wstring& a, const std::wstring& b) {
        return _wcsicmp(a.c_str(), b.c_str()) == 0;
    }
    DetectionResult failure(const std::string& name, const std::string& reason,
        const std::wstring& path, REGSAM view, LONG code) {
        return { true, name, reason, path, {errorText(code)}, viewLabel(view) };
    }
}

// Check boot & setup locations for persistence
DetectionResult bootPersist(REGSAM bitVer) {
    const std::wstring subkey = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager";
    const std::wstring path = L"HKLM\\" + subkey;
    auto opened = openRegistryKey(HKEY_LOCAL_MACHINE, subkey, bitVer);
    if (opened.status != ERROR_SUCCESS)
        return failure("Boot Persistence", "Failed to open registry key.", path, bitVer, opened.status);

    std::vector<std::wstring> details;
    std::wstring issue;
    bool suspicious = false;
    auto check = [&](const wchar_t* name, bool isBoot) {
        const std::wstring fullPath = path + L"\\" + name;
        auto read = readRegistryValue(opened.key.get(), name);
        if (!isBoot && (read.status == ERROR_FILE_NOT_FOUND || read.status == ERROR_PATH_NOT_FOUND)) {
            details.push_back(L"SetupExecute: <not present>");
            return;
        }

        std::vector<std::wstring> values;
        std::wstring err;
        if (!registryMultiString(read.value, values, err)) {
            suspicious = true;
            if (issue.empty()) issue = fullPath;
            details.push_back(std::wstring(name) + L": " + err);
            return;
        }
        if (values.empty()) details.push_back(std::wstring(name) + L": <empty>");
        for (const auto& v : values) details.push_back(std::wstring(name) + L": " + v);
        bool unexpected = isBoot ? (values.size() != 1 || values.front() != L"autocheck autochk *")
            : !values.empty();
        if (unexpected) {
            suspicious = true;
            if (issue.empty()) { issue = fullPath; }
        }
    };
    check(L"BootExecute", true);
    check(L"SetupExecute", false);
    return { suspicious, "Boot Persistence",
            suspicious ? "Unexpected BootExecute/SetupExecute configuration or read error."
                       : "No suspicious evidence found.",
            suspicious ? issue : path, details, viewLabel(bitVer) };
}

// IFEO check
DetectionResult ifeo(REGSAM bitVer) {
    const std::wstring subkey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    const std::wstring path = L"HKLM\\" + subkey;
    auto opened = openRegistryKey(HKEY_LOCAL_MACHINE, subkey, bitVer);
    if (opened.status != ERROR_SUCCESS)
        return failure("IFEO", "Failed to open registry key.", path, bitVer, opened.status);
    auto children = enumerateSubkeys(opened.key.get());
    if (children.status != ERROR_SUCCESS)
        return failure("IFEO", "Failed to enumerate executable subkeys.", path, bitVer, children.status);

    bool suspicious = false;
    std::wstring trigger;
    std::vector<std::wstring> details;
    for (const auto& exe : children.names) {
        const std::wstring fullPath = path + L"\\" + exe + L"\\Debugger";
        auto child = openRegistryKey(opened.key.get(), exe, 0);
        if (child.status != ERROR_SUCCESS) {
            suspicious = true;
            if (trigger.empty()) trigger = fullPath;
            details.push_back(L"[" + exe + L"] open failed: " + errorText(child.status));
            continue;
        }
        auto read = readRegistryValue(child.key.get(), L"Debugger");
        if ((read.status == ERROR_FILE_NOT_FOUND || read.status == ERROR_PATH_NOT_FOUND)) continue;
        if (read.status != ERROR_SUCCESS) {
            suspicious = true;
            if (trigger.empty()) trigger = fullPath;
            details.push_back(L"[" + exe + L"] read failed: " + errorText(read.status));
            continue;
        }
        std::wstring value, err;
        if (!registryString(read.value, value, err)) {
            suspicious = true;
            if (trigger.empty()) trigger = fullPath;
            details.push_back(L"[" + exe + L"] malformed Debugger: " + err);
            continue;
        }
        if (!value.empty()) {
            suspicious = true;
            if (trigger.empty()) trigger = fullPath;
            details.push_back(L"Debugger [" + exe + L"]: " + value);
        }
    }
    return { suspicious, "IFEO", suspicious ? "IFEO Debugger or read anomaly found."
                                            : "No IFEO Debugger values found.",
            suspicious ? trigger : path, details, viewLabel(bitVer) };
}

// Checks UserInit and Shell startup programs activated on user logon
DetectionResult winLogon(REGSAM bitVer) {
    const std::wstring subkey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    const std::wstring path = L"HKLM\\" + subkey;
    auto opened = openRegistryKey(HKEY_LOCAL_MACHINE, subkey, bitVer);
    if (opened.status != ERROR_SUCCESS) {return failure("Win Logon", "Failed to open registry key.", path, bitVer, opened.status);}

    wchar_t windowsDir[MAX_PATH]{};
    UINT length = GetWindowsDirectoryW(windowsDir, MAX_PATH);
    if (!length || length >= MAX_PATH) { return failure("Win Logon", "Unable to determine Windows directory.", path, bitVer, GetLastError()); }

    const std::vector<std::pair<std::wstring, std::wstring>> checks = {
        {L"Shell", L"explorer.exe"},
        {L"Userinit", std::wstring(windowsDir) + L"\\system32\\userinit.exe,"}
    };
    bool suspicious = false;
    std::wstring trigger;
    std::vector<std::wstring> details;
    for (const auto& [name, expected] : checks) {
        const std::wstring fullPath = path + L"\\" + name;
        auto read = readRegistryValue(opened.key.get(), name);

        if (read.status == ERROR_FILE_NOT_FOUND && name == L"Userinit" && bitVer == KEY_WOW64_32KEY) {
            details.push_back(L"[Userinit] Not present in 32-bit registry view.");
            continue;
        }
        if (read.status != ERROR_SUCCESS) {
            suspicious = true;
            if (trigger.empty()) { trigger = fullPath; }
            details.push_back(L"[" + name + L"] ERROR: " + errorText(read.status) + L" | " + fullPath);
            continue;
        }
        std::wstring value, err;
        if (!registryString(read.value, value, err)) {
            suspicious = true;
            if (trigger.empty()) { trigger = fullPath; }
            details.push_back(L"[" + name + L"] ERROR: " + err + L" | " + fullPath);
            continue;
        }
        details.push_back(L"[" + name + L"] Value: " + value);
        if (!equalIgnoreCase(value, expected)) {
            suspicious = true;
            if (trigger.empty()) { trigger = fullPath; }
            details.push_back(L"[" + name + L"] DETECTED: Unexpected configuration | " + fullPath);
        }
        else {
            details.push_back(L"[" + name + L"] CLEAN");
        }
    }
    return { suspicious, "Win Logon", suspicious ? "Unexpected or unreadable Winlogon values." : "No suspicious evidence found.", suspicious ? trigger : path, details, viewLabel(bitVer) };
}

// ToDo
DetectionResult lsa(REGSAM bitVer) {
    return { false, "LSA", "Not implemented; no scan performed.", L"", {}, viewLabel(bitVer) };
}

// ToDo
DetectionResult controlServices(REGSAM bitVer) {
    return { false, "Services", "Not implemented; no scan performed.", L"", {}, viewLabel(bitVer) };
}

// ToDo
DetectionResult activeSet(REGSAM bitVer) {
    return { false, "ActiveSet", "Not implemented; no scan performed.", L"", {}, viewLabel(bitVer) };
}

// ToDo
DetectionResult xxx(REGSAM bitVer) {
    return { false, "XXX", "Not implemented; no scan performed.", L"", {}, viewLabel(bitVer) };
}

// Function to help with RunKey reporting
std::vector<DetectionResult> runKeys(REGSAM bitVer, HKEY rootHive, const std::wstring& skeyPath, const std::wstring& sdisplayPath) {
    std::vector<DetectionResult> results;
    auto opened = openRegistryKey(rootHive, skeyPath, bitVer);
    if ((opened.status == ERROR_FILE_NOT_FOUND || opened.status == ERROR_PATH_NOT_FOUND)) { return results; }
    if (opened.status != ERROR_SUCCESS) {
        results.push_back(failure("RunKeys", "Failed to open registry key.", sdisplayPath, bitVer, opened.status));
        return results;
    }
    auto values = enumerateRegistryValues(opened.key.get());
    for (const auto& entry : values.values) {
        const std::wstring fullPath = sdisplayPath + L"\\" + entry.name;
        std::wstring command, err;
        if (!registryString(entry, command, err)) {
            results.push_back({ true, "RunKeys", "Invalid startup entry format.", fullPath, {err}, viewLabel(bitVer) });
            continue;
        }
        results.push_back({ true, "RunKeys", "Startup entry found", fullPath, {L"Command: " + command}, viewLabel(bitVer) });
    }
    if (values.status != ERROR_SUCCESS) {
        results.push_back(failure("RunKeys", "Failed to enumerate all startup values.", sdisplayPath, bitVer, values.status));
    }
    return results;
}

// Monitor Defender's configurations
DetectionResult defendKeys(REGSAM bitVer) {
    const std::vector<std::wstring> targets = {
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
        L"SOFTWARE\\Microsoft\\Windows Defender\\Features",
        L"SYSTEM\\CurrentControlSet\\Services\\WinDefend",
        L"SYSTEM\\CurrentControlSet\\Services\\WdNisSvc"
    };
    bool suspicious = false;
    std::wstring trigger;
    std::vector<std::wstring> details;

    for (const auto& subkey : targets) {
        const std::wstring path = L"HKLM\\" + subkey;
        auto opened = openRegistryKey(HKEY_LOCAL_MACHINE, subkey, bitVer);
        if (((opened.status == ERROR_FILE_NOT_FOUND || opened.status == ERROR_PATH_NOT_FOUND))) {
            if (subkey.find(L"\\Services\\WinDefend") != std::wstring::npos || subkey.find(L"\\Services\\WdNisSvc") != std::wstring::npos) {
                suspicious = true;
                if (trigger.empty()) { trigger = path; }
                details.push_back(path + L": Defender service key missing.");
            }
            continue;
        }
        if (opened.status != ERROR_SUCCESS) {
            suspicious = true;
            if (trigger.empty()) trigger = path;
            details.push_back(path + L": " + errorText(opened.status));
            continue;
        }

        auto values = enumerateRegistryValues(opened.key.get());
        if (values.status != ERROR_SUCCESS) {
            suspicious = true;
            if (trigger.empty()) trigger = path;
            details.push_back(path + L": enumeration failed, " + errorText(values.status));
            continue;
        }
        const bool exclusion = subkey.find(L"\\Exclusions\\") != std::wstring::npos;
        for (const auto& entry : values.values) {
            const std::wstring fullPath = path + L"\\" + entry.name;
            DWORD number = 0;
            const bool isDword = entry.type == REG_DWORD && entry.bytes.size() == sizeof(DWORD);
            if (isDword) std::memcpy(&number, entry.bytes.data(), sizeof(number));
            bool flagged = exclusion;

            if (isDword) {
                if ((entry.name == L"DisableAntiSpyware" || entry.name == L"DisableAntiVirus" || entry.name == L"DisableRealtimeMonitoring" || entry.name == L"DisableBehaviorMonitoring" || entry.name == L"DisableScriptScanning" || entry.name == L"DisableScanningNetworkFiles") && number != 0) { flagged = true; }
                if ((entry.name == L"TamperProtection" || entry.name == L"PUAProtection") && number == 0) { flagged = true; }
                if (entry.name == L"Start" && number == 4 && (subkey.find(L"\\Services\\WinDefend") != std::wstring::npos || subkey.find(L"\\Services\\WdNisSvc") != std::wstring::npos)) { flagged = true; }
            }else if ((entry.name == L"DisableAntiSpyware" || entry.name == L"DisableAntiVirus" || entry.name == L"DisableRealtimeMonitoring" || entry.name == L"DisableBehaviorMonitoring" || entry.name == L"DisableScriptScanning" || entry.name == L"DisableScanningNetworkFiles" || entry.name == L"TamperProtection" || entry.name == L"PUAProtection") && !isDword) {
                flagged = true;
            }

            if (flagged) {
                suspicious = true;
                if (trigger.empty()) trigger = fullPath;
                auto displayBytes = entry.bytes;
                details.push_back(fullPath + L" [" + registryTypeName(entry.type) + L"] = " + registryDataToString(entry.type, displayBytes, static_cast<DWORD>(displayBytes.size())));
            }
        }
    }
    return { suspicious, "Defender", suspicious ? "Defender configuration findings or read errors." : "No Defender values flagged.", suspicious ? trigger : L"HKLM\\SOFTWARE\\Microsoft\\Windows Defender", details, viewLabel(bitVer) };
}

// Reports the result of a check and queues flagged checks
void reportResult(const DetectionResult& result) {
    std::cout << "[" << result.name << "]\n" << "\t[-] Version : " << result.registryView << "\n" << "\t[-] Result: " << (result.suspicious ? "FLAGGED" : "CLEAN") << "\n" << "\t[-] Reason: " << result.reason << "\n";
    if (!result.triggerPath.empty()) { std::wcout << L"\t[-] Registry: " << result.triggerPath << L"\n"; }
    for (const auto& detail : result.details) {
        std::wcout << L"\t[-] " << detail << L"\n";
    }
    if (result.suspicious) queueAlert(result);
}

// Allowlist for RunKey entries
BOOL isValidRunEntry(const DetectionResult& result) {
    if (result.name != "RunKeys" || result.reason != "Startup entry found") { return FALSE; }
    const std::vector<std::wstring> allowed = {
        L"%windir%\\system32\\SecurityHealthSystray.exe",
        L"C:\\system32\\SecurityHealthSystray.exe",
        L"C:\\Program Files\\Netbird\\Netbird - ui.exe",
        L"C:\\Program Files\\Netbird\\Netbird-ui.exe",
        L"\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --no-startup-window --win-session-start",
        L"placeholder"
    };
    for (const auto& detail : result.details)
        for (const auto& known : allowed)
            if (detail.find(known) != std::wstring::npos) return TRUE;
    return FALSE;
}

// Checks various RunKey locations for persistence
void regRunner() {
    const std::wstring base = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\";
    const std::vector<std::wstring> paths = {
        base + L"Run", 
        base + L"RunOnce",
        base + L"Policies\\Explorer\\Run", 
        base + L"RunServices"
    };
    for (const auto& path : paths) {
        for (HKEY root : {HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE}) {
            const std::wstring display = hiveLabel(root) + L"\\" + path;

            for (REGSAM view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY}) {
                auto results = runKeys(view, root, path, display);
                if (results.empty() && display.find(L"RunServices") == std::wstring::npos) { std::wcout << L"[RunKeys] No entries found in " << display << L" (" << (view == KEY_WOW64_64KEY ? L"64" : L"32") << L")\n"; }
                if (results.empty() && display.find(L"RunServices") != std::wstring::npos) { std::wcout << L"[RunKeys] No legacy entries found in " << display << L" (" << (view == KEY_WOW64_64KEY ? L"64" : L"32") << L")\n"; }
                for (const auto& result : results) {
                    if (isValidRunEntry(result)) { continue; }
                    reportResult(result);
                }
            }
        }
    }
}

// Put checks here if you want the program to run them
void regScan() {
    std::lock_guard<std::mutex> lock(cmdMutex);
    std::cout << "## Scanning For Suspicious Registry Keys ##\n";
    reportResult(bootPersist(KEY_WOW64_64KEY));
    reportResult(bootPersist(KEY_WOW64_32KEY));
    reportResult(winLogon(KEY_WOW64_64KEY));
    reportResult(winLogon(KEY_WOW64_32KEY));
    regRunner();
    reportResult(ifeo(KEY_WOW64_64KEY));
    reportResult(ifeo(KEY_WOW64_32KEY));
    reportResult(defendKeys(KEY_WOW64_64KEY));
    reportResult(defendKeys(KEY_WOW64_32KEY));
}
