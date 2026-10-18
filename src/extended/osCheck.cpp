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
                // https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getproductinfo 
                if (GetProductInfo(osInfo.dwMajorVersion, osInfo.dwMinorVersion, 0, 0, &productType)) {
                    switch (productType) {
                    case PRODUCT_CORE:
                        std::cout << "\tProduct Type: " << "Home" << std::endl;
                        break;
                    case PRODUCT_CORE_N:
                        std::cout << "\tProduct Type: " << "Home (EU edition?)" << std::endl;
                        break;
                    case PRODUCT_CORE_COUNTRYSPECIFIC:
                        std::cout << "\tProduct Type: " << "Home (Chinese edition?)" << std::endl;
                        break;
                    case PRODUCT_CLUSTER_SERVER:
                        std::cout << "\tProduct Type: " << "Cluster Server HPC" << std::endl;
                        break;
                    case PRODUCT_CLUSTER_SERVER_V:
                        std::cout << "\tProduct Type: " << "Server Hyper Core V" << std::endl;
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
                    case PRODUCT_ENTERPRISE_N:
                        std::cout << "\tProduct Type: " << "Enterprise (EU edition?)" << std::endl;
                        break;
                    case PRODUCT_HOME_BASIC:
                        std::cout << "\tProduct Type: " << "Home" << std::endl;
                        break;
                    case PRODUCT_HOME_BASIC_N:
                        std::cout << "\tProduct Type: " << "Home (EU edition?)" << std::endl;
                        break;
                    case PRODUCT_HYPERV:
                        std::cout << "\tProduct Type: " << "Microsoft Hyper-V Server" << std::endl;
                        break;
                    case PRODUCT_SMALLBUSINESS_SERVER:
                        std::cout << "\tProduct Type: " << "Small Business Server" << std::endl;
                        break;
                    case PRODUCT_PROFESSIONAL:
                        std::cout << "\tProduct Type: " << "Professional" << std::endl;
                        break;
                    case PRODUCT_PROFESSIONAL_N:
                        std::cout << "\tProduct Type: " << "Professional (EU edition?)" << std::endl;
                        break;
                    case PRODUCT_PRO_WORKSTATION:
                        std::cout << "\tProduct Type: " << "Win 10 Pro Workstation" << std::endl;
                        break;
                    case PRODUCT_STANDARD_SERVER:
                        std::cout << "\tProduct Type: " << "Windows Server" << std::endl;
                        break;
                    case PRODUCT_ULTIMATE:
                        std::cout << "\tProduct Type: " << "Windows 7 or Vista" << std::endl;
                        std::cout << "\tProduct Type: " << "R.I.P. security. Good luck soldier o7" << std::endl;
                        break;
                    case PRODUCT_ULTIMATE_N:
                        std::cout << "\tProduct Type: " << "Windows 7 or Vista (EU edition?)" << std::endl;
                        std::cout << "\tProduct Type: " << "R.I.P. security. Good luck soldier o7" << std::endl;
                        break;
                    case PRODUCT_WEB_SERVER:
                        std::cout << "\tProduct Type: " << "Windows Web Server Full" << std::endl;
                        break;
                    case PRODUCT_WEB_SERVER_CORE:
                        std::cout << "\tProduct Type: " << "Windows Web Server Core" << std::endl;
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