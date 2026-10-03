#pragma once

#include <string>
#include <vector>
#include <windows.h>

struct DetectionResult{
    bool suspicious;
    std::string name;
    std::string reason;
    std::wstring triggerPath;
    std::vector<std::wstring> details;
    std::string registryView;
};

inline std::wstring registryTypeName(DWORD type){
    switch (type){
    case REG_SZ:
        return L"REG_SZ";
    case REG_EXPAND_SZ:
        return L"REG_EXPAND_SZ";
    case REG_MULTI_SZ:
        return L"REG_MULTI_SZ";
    case REG_DWORD:
        return L"REG_DWORD";
    case REG_QWORD:
        return L"REG_QWORD";
    case REG_BINARY:
        return L"REG_BINARY";
    case REG_NONE:
        return L"REG_NONE";
    default:
        return L"UNKNOWN";
    }
}

inline std::wstring registryDataToString(DWORD type, const std::vector<BYTE>& data, DWORD dataSize){
    if (type == REG_DWORD && dataSize >= sizeof(DWORD)){
        DWORD value = 0;
        memcpy(&value, data.data(), sizeof(DWORD));
        return std::to_wstring(value);
    }

    if (type == REG_QWORD && dataSize >= sizeof(ULONGLONG)){
        ULONGLONG value = 0;
        memcpy(&value, data.data(), sizeof(ULONGLONG));
        return std::to_wstring(value);
    }

    if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ){
        if (dataSize == 0) { return L""; }

        std::wstring value(reinterpret_cast<const wchar_t*>(data.data()), dataSize / sizeof(wchar_t));

        while (!value.empty() && value.back() == L'\0'){value.pop_back();}

        for (wchar_t& character : value){
            if (character == L'\0'){ character = L';'; }
        }
        return value;
    }
    return L"";
}