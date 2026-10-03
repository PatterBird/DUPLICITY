#pragma once
#include "../../Microsoft.O365.Security.Krabsetw.4.4.2/lib/native/include/krabs.hpp"

// Attaches proccess creation logging to ETW session
void MonitorProcessCreate(krabs::user_trace& trace, krabs::provider<>& provider);