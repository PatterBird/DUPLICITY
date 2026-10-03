//API function documentation: learn.microsoft.com/ru-ru/windows/win32/api/winuser/nf-winuser-messagebox
#include "winbox.h"
#include <windows.h>

// These alerts are for high priority notices that reccommend imediate review.
void noticeTermination() {
	// Alert when DUPLICITY is taken offline - possible attack
	MessageBox(NULL, L"Someone is trying to terminate the consumer, and was perhaps sucessfull in doing so. This action will be logged for review", L"DUPLICITY TERMINATION", MB_OK | MB_ICONSTOP | MB_TOPMOST);
}

// Add logic to disbale this if user wants to.
void popREGAlert(const DetectionResult& result) {
    std::wstring message;

    message += L"Name: ";
    message += std::wstring(result.name.begin(), result.name.end());
    message += L"\n";

    message += L"Version: ";
    message += std::wstring(result.registryView.begin(), result.registryView.end());
    message += L"\n";

    message += L"Location: ";
    message += result.triggerPath;
    message += L"\n";

    message += L"Reason: ";
    message += std::wstring(result.reason.begin(), result.reason.end());
    message += L"\n";


    if (!result.details.empty()) {
        message += L"Details:\n";
        for (const auto& detail : result.details) {
            message += L"- ";
            message += detail;
            message += L"\n";
        }
    }

	MessageBoxW(NULL, message.c_str(), L"Registry Item Flagged", MB_OK | MB_ICONWARNING | MB_TOPMOST);

}


void alertXYZ() {
	// Test alert
	int susAttack = MessageBox(NULL, L"Test123", L"XYZ ATTACK SUSPECTED", MB_YESNO | MB_ICONSTOP | MB_TOPMOST);
	if (susAttack == IDYES) {
		MessageBox(NULL, L"Expanding info...", L"XYZ ATTACK SUSPECTED", MB_OK);
	} else if (susAttack == IDNO) {
		MessageBox(NULL, L"Understood.", L"XYZ ATTACK SUSPECTED", MB_OK);
	}

}


