#pragma once

#include "./sharedHeaders/detRes.h"
#include <Windows.h>

// Add an alert to the queue
void queueAlert(const DetectionResult& result);

void alertWorker();

void haltAlertWorker();

BOOL WINAPI termKill(DWORD signal);