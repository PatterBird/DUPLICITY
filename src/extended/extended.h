#pragma once
#include "../reporting/sharedHeaders/detRes.h"

// OS Check
void osCheck();

// Registry Check
void regScan();

// Event Viewer Check

// Task Scheduler Check
void taskCheck();

// User Audit
void userAudit();

// MS Defender
void MSDefend();
// Called by regScan()
DetectionResult defenderServiceCheck();
DetectionResult defenderDriverCheck();