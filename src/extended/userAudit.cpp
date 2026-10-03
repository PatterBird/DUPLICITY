//Local users & permissions: https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuserenum
//Domain users & permission / info
#include "extended.h"
#include "../reporting/winbox.h"
#include "../reporting/sharedHeaders/safeWrite.h"
#include <Windows.h>
#include <LM.h>
#include <iostream>
#include <ctime>
#pragma comment(lib, "netapi32.lib")

void printUserGroups(const wchar_t* usrname);

void localUsers() {
    NET_API_STATUS localStat;
    LPUSER_INFO_3 pBuff = NULL;
    LPUSER_INFO_3 pTemp = NULL;
    DWORD entryCount = 0;
    DWORD entryTotal = 0;
    DWORD dwResumeHandle = 0;
    
    localStat = NetUserEnum(NULL, 3, 0, (LPBYTE*)&pBuff, MAX_PREFERRED_LENGTH, &entryCount, &entryTotal, &dwResumeHandle);

    if (localStat == NERR_Success) {

        if ((pTemp = pBuff) != NULL) {

            for (DWORD i = 0; i < entryCount; i++) {
                if (pTemp == NULL) {break;}
                DWORD formatSec = pTemp->usri3_password_age;

                std::wcout << L"\n[+] Local User: " << pTemp->usri3_name << std::endl;
                printUserGroups(pTemp->usri3_name);
                std::wcout << L"\t[-] ID: " << pTemp->usri3_user_id << std::endl;
                
                if (formatSec >= 86400) { std::wcout << L"\t[-] Password Age: " << ((formatSec / 60) / 60) /24 << L" days(s)\n"; }
                else if ((formatSec >= 3600) && (formatSec < 86400)) { std::wcout << L"\t[-] Password Age: " << (formatSec / 60) /60 << L" hour(s)\n"; }
                else if ((formatSec >= 60) && formatSec < 3600){std::wcout << L"\t[-] Password Age: " << formatSec / 60 << L" min\n";}
                else {std::wcout << L"\t[-] Password Age: " << formatSec << L" sec\n";}
                
                time_t unixLogon = static_cast<time_t>(pTemp->usri3_last_logon);
                tm localTime{};
                if (unixLogon == 0) { std::wcout << L"\t[-] Last Logon: NEVER" << std::endl; }
                else {
                    if (localtime_s(&localTime, &unixLogon) == 0) {
                        std::wcout << L"\t[-] Last Logon: " << localTime.tm_year + 1900 << L"/" << localTime.tm_mon + 1 << L"/" << localTime.tm_mday << L" " << localTime.tm_hour << L":" << localTime.tm_min << L":" << localTime.tm_sec << L"\n";
                    }
                }

                std::wcout << L"\t[-] Logon Count: " << pTemp->usri3_num_logons << std::endl;

                if (pTemp->usri3_flags & UF_ACCOUNTDISABLE) {
                    std::cout << "\t[-] Account is disabled" << std::endl;
                }
                if (pTemp->usri3_flags & UF_LOCKOUT) {
                    std::cout << "\t[-] Account is locked" << std::endl;
                }
                pTemp++;
            }
        }
    }
    else {
        std::cout << "Local User Enum Failed!\n" << std::endl;
    }

    if (pBuff != NULL) {
        NetApiBufferFree(pBuff);
    }
}

void printUserGroups(const wchar_t* usrname)
{
    LPLOCALGROUP_USERS_INFO_0 groupBuffer = nullptr;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;

    NET_API_STATUS status = NetUserGetLocalGroups(NULL, usrname, 0, LG_INCLUDE_INDIRECT, (LPBYTE*)&groupBuffer, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries);

    if (status == NERR_Success)
    {
        for (DWORD i = 0; i < entriesRead; i++){
            std::wcout << L"\t[-] Group(s): " << groupBuffer[i].lgrui0_name << std::endl;
        }
    }
    else {
        std::wcout << L"\t[?] Group(s): N/A" << std::endl;
    }

    if (groupBuffer != nullptr) {
        NetApiBufferFree(groupBuffer);
    }
}

void domainUsers() {
    NET_API_STATUS domainStatus;
    NETSETUP_JOIN_STATUS connStatus;
    LPWSTR domainName = NULL;
    LPBYTE dcBuffer = NULL;

    domainStatus = NetGetJoinInformation(NULL, &domainName, &connStatus);
    if (domainStatus != NERR_Success) {
        std::wcout << L"Failed to get DC join information. Error: " << domainStatus << std::endl;
        return;
    }
    if (connStatus != NetSetupDomainName || domainName == NULL) {
        std::cout << "This machine is not joined to a domain. Domain user audit skipped." << std::endl;
        if (domainName != NULL){
            NetApiBufferFree(domainName);
        }
        return;
    }

    //If the machine is connected, then it will grab the users here
    std::wcout << L"\t[!] Connected Domain: " << domainName << std::endl;

    domainStatus = NetGetDCName(NULL, domainName, &dcBuffer);
    if (domainStatus != NERR_Success) {
        std::wcout << L"Failed to locate Domain Controller. Error: " << domainStatus << std::endl;
        NetApiBufferFree(domainName);
    }
    else {
        LPWSTR dcName = (LPWSTR)dcBuffer;
        std::wcout << L"Domain Controller: " << dcName << std::endl;

        LPUSER_INFO_3 pBuff = NULL;
        LPUSER_INFO_3 pTemp = NULL;
        DWORD entryCount = 0;
        DWORD entryTotal = 0;
        DWORD dwResumeHandle = 0;

        domainStatus = NetUserEnum(dcName, 3, 0, (LPBYTE*)&pBuff, MAX_PREFERRED_LENGTH, &entryCount, &entryTotal, &dwResumeHandle);

        if (domainStatus == NERR_Success) {

            if ((pTemp = pBuff) != NULL) {
                for (DWORD i = 0; i < entryCount; i++) {
                    if (pTemp == NULL) { break; }
                    DWORD formatSec = pTemp->usri3_password_age;

                    std::wcout << L"\n[+] Domain User: " << pTemp->usri3_name << std::endl;
                    std::wcout << L"\t[-] ID: " << pTemp->usri3_user_id << std::endl;

                    if (formatSec >= 86400) { std::wcout << L"\t[-] Password Age: " << ((formatSec / 60) / 60) / 24 << L" days(s)\n"; }
                    else if ((formatSec >= 3600) && (formatSec < 86400)) { std::wcout << L"\t[-] Password Age: " << (formatSec / 60) / 60 << L" hour(s)\n"; }
                    else if ((formatSec >= 60) && formatSec < 3600) { std::wcout << L"\t[-] Password Age: " << formatSec / 60 << L" min\n"; }
                    else { std::wcout << L"\t[-] Password Age: " << formatSec << L" sec\n"; }

                    time_t unixLogon = static_cast<time_t>(pTemp->usri3_last_logon);
                    tm localTime{};
                    if (unixLogon == 0) { std::wcout << L"\t[-] Last Logon: NEVER" << std::endl; }
                    else {
                        if (localtime_s(&localTime, &unixLogon) == 0) {
                            std::wcout << L"\t[-] Last Logon: " << localTime.tm_year + 1900 << L"/" << localTime.tm_mon + 1 << L"/" << localTime.tm_mday << L" " << localTime.tm_hour << L":" << localTime.tm_min << L":" << localTime.tm_sec << L"\n";
                        }
                    }

                    std::wcout << L"\t[-] Logon Count: " << pTemp->usri3_num_logons << std::endl;

                    if (pTemp->usri3_flags & UF_ACCOUNTDISABLE) {
                        std::cout << "\t[-] Account is disabled" << std::endl;
                    }
                    if (pTemp->usri3_flags & UF_LOCKOUT) {
                        std::cout << "\t[-] Account is locked" << std::endl;
                    }
                    pTemp++;
                }
            }
        }
        else {
            std::cout << "Domain User Enum Failed!\n" << std::endl;
        }

        if (pBuff != NULL) {
            NetApiBufferFree(pBuff);
            pBuff = NULL;
        }
        if (domainName) { NetApiBufferFree(domainName); }
        if (dcBuffer) { NetApiBufferFree(dcBuffer); }
    }
}

void userAudit() {
    std::lock_guard<std::mutex> lock(cmdMutex);

    std::cout << "## Auditing Users & Groups ##\n";

    localUsers();
    domainUsers();

}