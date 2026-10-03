#pragma once
#include "./sharedHeaders/detRes.h"

// Extended feature popups
void popREGAlert(const DetectionResult& result);

// Consumer termination boxes
void noticeTermination();

// Suspected XYZ type of attack boxes
void alertXYZ();