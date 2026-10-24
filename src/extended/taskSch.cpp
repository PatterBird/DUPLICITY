#include <windows.h>
#include <comdef.h>
#include <taskschd.h>
#include <iostream>
#include "../reporting/sharedHeaders/detRes.h"
#include "../reporting/sharedHeaders/safeWrite.h"

#pragma comment(lib, "taskschd.lib")

// PS > Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\CLSID\*" | Select - Object PSChildName, '(default)' | Format - Table - AutoSize | Out - String - Stream | Select - "Task Sch"
// https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskfolder-gettasks 

/*
SCORE SYSTEM:
Elevated Priv: +2 //done
SYSTEM User: +1 // dome
Hidden: +1  // done
Recent creation (past 2 days): +2
Calls PS or CMD: +5 // done
Sus exe directory: +5 // done
Logon / Startup: +3
other??? +0
FLAGGED THREASHOLD: 5 points
*/

constexpr int SCORE_THRESH = 5;
std::vector<TaskSchResult> enumTasks(ITaskFolder* folder);

void taskCheck(){
    std::lock_guard<std::mutex> lock(cmdMutex);

    // Initialize COM library
    HRESULT comThing = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (comThing < 0) {
        std::wcout << "\n[!] TaskSch COM initilization failed!" << std::endl;
        return;
    }

    /*// Initialize security.
    comThing = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (comThing < 0) {
        CoUninitialize();
        std::wcout << "\n[!] TaskSch COM security initilization failed!" << std::endl;
        return;
    }*/

    // Summon Task Scheduler
    ITaskService* pService = NULL;
    comThing = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
    if (comThing < 0) {
        CoUninitialize();
        std::wcout << "\n[!] TaskSch COM CoCreateInstance() failed!" << std::endl;
        return;
    }

    // Connect to Task Scheduler
    comThing = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (comThing < 0) {
        pService->Release();
        CoUninitialize();
        std::wcout << "\n[!] COM connection to TaskSch failed!" << std::endl;
        return;
    }

    // Open the Root Task Folder ("\")
    ITaskFolder* pRootFolder = NULL;
    comThing = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    pService->Release();
    if (comThing < 0) {
        CoUninitialize();
        std::wcout << "\n[!] TaskSch could not be opened!" << std::endl;
        return;
    }

    // Get the collection of registered tasks
    auto results = enumTasks(pRootFolder);
    pRootFolder->Release();
    CoUninitialize();

    // Print findings after enumeration finishes.
    for (const auto& result : results) {
        std::cout << "\n[" << result.name << "]\n";
        std::cout << "\t[-] Result: " << (result.suspicious ? "FLAGGED" : "CLEAN") << "\n";
        std::cout << "\t[-] Reason: " << result.reason << "\n";
        std::wcout << L"\t[-] Task: " << result.triggerPath << L"\n";
        for (const auto& detail : result.details) {
            std::wcout << L"\t" << detail << std::endl;
        }
    }
    std::cout << "\n[!] Number of findings: " << results.size() << std::endl;;
}

std::vector<TaskSchResult> enumTasks(ITaskFolder* folder) {
    std::vector<TaskSchResult> findings;
    if (!folder){ return findings; }

    IRegisteredTaskCollection* tasks = nullptr;
    HRESULT registeredTasks = folder->GetTasks(TASK_ENUM_HIDDEN, &tasks);

    if (SUCCEEDED(registeredTasks) && tasks) {
        LONG taskIndex = 0;

        if (SUCCEEDED(tasks->get_Count(&taskIndex))) {
            for (LONG i = 1; i <= taskIndex; ++i) {
                IRegisteredTask* task = nullptr;

                if (FAILED(tasks->get_Item(_variant_t(i), &task)) || !task) { continue; }

                // Each task gets its own score and details.
                int score = 0;
                std::vector<std::wstring> details;

                BSTR taskName = nullptr;
                BSTR taskPath = nullptr;
                VARIANT_BOOL enabled = VARIANT_FALSE;
                VARIANT_BOOL hidden = VARIANT_FALSE;

                task->get_Name(&taskName);
                task->get_Path(&taskPath);
                task->get_Enabled(&enabled);

                const std::wstring name = taskName ? taskName : L"<unknown>";
                const std::wstring path = taskPath ? taskPath : L"<unknown>";

                details.push_back(L"\t[-] Name: " + name);
                details.push_back(L"\t[-] Path: " + path);
                details.push_back(std::wstring(L"\t[-] Enabled: ") + (enabled == VARIANT_TRUE ? L"Yes" : L"No"));

                ITaskDefinition* definition = nullptr;

                if (SUCCEEDED(task->get_Definition(&definition)) && definition) {
                    IPrincipal* principal = nullptr;

                    if (SUCCEEDED(definition->get_Principal(&principal)) && principal) {
                        BSTR userId = nullptr;
                        TASK_RUNLEVEL_TYPE runLevel = TASK_RUNLEVEL_LUA;

                        if (SUCCEEDED(principal->get_RunLevel(&runLevel))) {
                            bool elevated = (runLevel == TASK_RUNLEVEL_HIGHEST);
                            details.push_back(std::wstring(L"\t[-]Privileges: ") + (elevated ? L"Highest" : L"Standard"));

                            if (elevated) {
                                score += 2;
                                details.push_back( L"\t\t[+2] Highest privileges requested");
                            }
                        }

                        if (SUCCEEDED(principal->get_UserId(&userId)) && userId) {
                            details.push_back(L"\t[-] User: " + std::wstring(userId));
                            const bool isSystem = (_wcsicmp(userId, L"SYSTEM") == 0 || _wcsicmp(userId, L"NT AUTHORITY\\SYSTEM") == 0 || _wcsicmp(userId, L"S-1-5-18") == 0);

                            if (isSystem) {
                                score += 1;
                                details.push_back(L"\t\t[+1] Runs as SYSTEM (NT)");
                            }
                        }
                        ITaskSettings* pTaskSettings = nullptr;
                        if (SUCCEEDED(definition->get_Settings(&pTaskSettings)) && pTaskSettings) {
                            VARIANT_BOOL isHidden = VARIANT_FALSE;

                            if (SUCCEEDED(pTaskSettings->get_Hidden(&isHidden)) && isHidden == VARIANT_TRUE) {
                                score += 1;
                                details.push_back(L"\t[-] Task: Marked as hidden");
                                details.push_back(L"\t\t[+1] Hidden");
                            }
                            pTaskSettings->Release();
                        }
                        /*IRegistrationInfo* regInfo = nullptr;
                        if (SUCCEEDED(definition->get_RegistrationInfo(&regInfo)) && regInfo) {
                            BSTR creationDate = nullptr;
                            FILETIME now{};
                            SYSTEMTIME createdSystem{};

                            ULARGE_INTEGER current{};
                            current.LowPart = now.dwLowDateTime;
                            current.HighPart = now.dwHighDateTime;

                            ULARGE_INTEGER created{};
                            created.LowPart = now.dwLowDateTime;
                            created.HighPart = now.dwHighDateTime;

                            constexpr ULONGLONG attackWindow = 48ULL * 60 * 60 * 10000000ULL;

                            if (current.QuadPart >= created.QuadPart && current.QuadPart - created.QuadPart <= attackWindow) {
                                score += 3;
                                details.push_back(L"\t[-] Created: " + std::wstring(creationDate));
                                details.push_back(L"\t\t[+3] Recently created");
                            }
                            SysFreeString(creationDate);
                            regInfo->Release();
                        }*/
                        SysFreeString(userId);
                        principal->Release();
                    }

                    IActionCollection* actions = nullptr;

                    if (SUCCEEDED(definition->get_Actions(&actions)) && actions) {
                        LONG actionCount = 0;

                        if (SUCCEEDED(actions->get_Count(&actionCount))) {
                            for (LONG a = 1; a <= actionCount; ++a) {
                                IAction* action = nullptr;

                                if (FAILED(actions->get_Item(a, &action)) || !action){ continue; }
                                
                                TASK_ACTION_TYPE actionType = TASK_ACTION_EXEC;

                                if (FAILED(action->get_Type(&actionType))) {
                                    action->Release();
                                    continue;
                                }

                                if (actionType == TASK_ACTION_EXEC) {
                                    IExecAction* exec = nullptr;

                                    if (SUCCEEDED(action->QueryInterface(
                                        IID_IExecAction,
                                        reinterpret_cast<void**>(&exec))) && exec) {

                                        BSTR exePath = nullptr;
                                        BSTR arguments = nullptr;

                                        exec->get_Path(&exePath);
                                        exec->get_Arguments(&arguments);

                                        std::wstring executable = exePath ? exePath : L"<no exe path>";

                                        std::wstring args = arguments ? arguments : L"<no args>";

                                        details.push_back(L"\t[-] Executable: " + executable );

                                        details.push_back(L"\t[-] Arguments: " + args);

                                        std::wstring command = executable + L" " + args;

                                        // Simple case-insensitive matching.
                                        for (auto& c : command) {
                                            c = static_cast<wchar_t>(towlower(c));
                                        }

                                        if (command.find(L"\\appdata\\") != std::wstring::npos || command.find(L"\\temp\\") != std::wstring::npos || command.find(L"\\downloads\\") != std::wstring::npos) {
                                            score += 5;
                                            details.push_back(L"\t\t[+5] Suspicious execution location");
                                        }
                                        if (command.find(L"powershell.exe") != std::wstring::npos || command.find(L"pwsh.exe") != std::wstring::npos || command.find(L"wscript.exe") != std::wstring::npos || command.find(L"cscript.exe") != std::wstring::npos || command.find(L"mshta.exe") != std::wstring::npos) {
                                            score += 5;
                                            details.push_back(L"\t\t[+5] Script execution");
                                        }
                                        SysFreeString(exePath);
                                        SysFreeString(arguments);
                                        exec->Release();
                                    }
                                }
                                else {
                                    details.push_back(L"\t[-] Action Type: " + std::to_wstring(static_cast<int>(actionType)));
                                }
                                action->Release();
                            }
                        }
                        actions->Release();
                    }
                    definition->Release();
                }
                details.push_back(L" [!] Total Score: " + std::to_wstring(score));

                if (score >= SCORE_THRESH) {
                    findings.push_back({
                        true,
                        "Scheduled Task",
                        "Task exceeded suspicious activity threshold.",
                        path,
                        details
                        });
                }
                SysFreeString(taskName);
                SysFreeString(taskPath);
                task->Release();
            }
        }
        tasks->Release();
    }

    // Recurse
    ITaskFolderCollection* folders = nullptr;
    registeredTasks = folder->GetFolders(0, &folders);

    if (SUCCEEDED(registeredTasks) && folders) {
        LONG count = 0;

        if (SUCCEEDED(folders->get_Count(&count))) {
            for (LONG i = 1; i <= count; ++i) {
                ITaskFolder* child = nullptr;

                if (SUCCEEDED(folders->get_Item(_variant_t(i), &child)) && child) {
                    auto childFindings = enumTasks(child);
                    findings.insert(findings.end(), childFindings.begin(), childFindings.end());

                    child->Release();
                }
            }
        }
        folders->Release();
    }
    return findings;
}
