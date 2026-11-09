#pragma once
#include <string>
#include "types.h"

namespace netguard::alert {

// Returns human-readable, legitimate response options an operator can
// take against a suspicious LAN device, for display in the dashboard.
// Deliberately does NOT include deauthentication or jamming: those
// affect the whole channel/network, not just the target, and are not
// something this tool will automate. These are the actions a real
// enterprise WIDS/NAC system (e.g. Cisco ISE, Aruba ClearPass) exposes
// to a human operator once a rogue device is identified.
std::string suggestedLanResponse(const LanDevice& dev);

// Same, for a rogue/suspicious access point.
std::string suggestedWifiResponse(const WifiAP& ap);

} // namespace netguard::alert
