#include "extended.h"
#include <windows.h>
#include <iostream>
#include <vector>

typedef NTSTATUS(WINAPI* LPFN_RTLGETVERSION)(PRTL_OSVERSIONINFOW);

void kernInfo() {
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (hNtDll) {
        LPFN_RTLGETVERSION pRtlGetVersion = (LPFN_RTLGETVERSION)GetProcAddress(hNtDll, "RtlGetVersion");
        if (pRtlGetVersion) {
            RTL_OSVERSIONINFOW osInfo = {};
            osInfo.dwOSVersionInfoSize = sizeof(osInfo);

            if (pRtlGetVersion(&osInfo) == 0) {
                std::cout << "\tMajor: " << osInfo.dwMajorVersion << std::endl;
                std::cout << "\tMinor: " << osInfo.dwMinorVersion << std::endl;
                std::cout << "\tBuild: " << osInfo.dwBuildNumber << std::endl;

                DWORD productType = 0;
                if (GetProductInfo(osInfo.dwMajorVersion, osInfo.dwMinorVersion, 0, 0, &productType)) {
                    switch (productType) {
                    case PRODUCT_CORE:
                        std::cout << "\tProduct Type: " << "Home" << std::endl;
                        break;
                    case PRODUCT_DATACENTER_SERVER:
                        std::cout << "\tProduct Type: " << "Windows Datacenter" << std::endl;
                        break;
                    case PRODUCT_EDUCATION:
                        std::cout << "\tProduct Type: " << "Education" << std::endl;
                        break;
                    case PRODUCT_ENTERPRISE:
                        std::cout << "\tProduct Type: " << "Enterprise" << std::endl;
                        break;
                    case PRODUCT_HOME_BASIC:
                        std::cout << "\tProduct Type: " << "Home" << std::endl;
                        break;
                    case PRODUCT_PROFESSIONAL:
                        std::cout << "\tProduct Type: " << "Professional" << std::endl;
                        break;
                    case PRODUCT_STANDARD_SERVER:
                        std::cout << "\tProduct Type: " << "Windows Server" << std::endl;
                        break;
                    default:
                        std::cout << "\tProduct Type: " << "Other" << std::endl;
                        break;
                    }
                }
            }
            else {
                std::wcout << L"UNKNOWN VERSION INFO - Nt!RtlGetVersion failed" << std::endl;
                return;
            }
        }
        else {
            std::wcout << L"UNKNOWN VERSION INFO - Nt!RtlGetVersion failed" << std::endl;
            return;
        }
    }
    else {
        std::wcout << L"UNKNOWN VERSION INFO" << std::endl;
        return;
    }
}

void osCheck() {
    DWORD buffSize = MAX_COMPUTERNAME_LENGTH + 1;
    std::vector<wchar_t> buffer(buffSize);

    if (GetComputerNameW(buffer.data(), &buffSize)) {
        std::wcout << L"Computer Name (NetBIOS): " << buffer.data() << std::endl;
    }else {
        std::wcout << L"Computer Name (NetBIOS): UNKNOWN" << std::endl;
    }

    // Extra Info
    kernInfo();

    std::wcout << L"\n";
}