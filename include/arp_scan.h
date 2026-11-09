#pragma once
#include <string>
#include "types.h"

namespace netguard::arpscan {

// Describes the local interface to scan on.
struct IfaceInfo {
    std::string name;
    std::string ipStr;
    std::string macStr;
    uint32_t ip = 0;     // host byte order
    uint32_t netmask = 0;
    bool valid = false;
};

// Finds the first usable, non-loopback IPv4 interface that is UP.
// Pass a preferred name (e.g. "wlan0") or "" to auto-detect.
IfaceInfo detectInterface(const std::string& preferredName);

// Runs one ARP sweep of the interface's /24 (or actual netmask) subnet,
// sending ARP "who-has" requests and collecting replies for `timeoutMs`.
// Results are merged into `state` (new devices get firstSeen=now,
// trust=Unknown unless already known; existing devices get lastSeen
// refreshed). Requires raw socket privileges (root / CAP_NET_RAW).
//
// Returns the number of devices seen in this sweep.
int sweepOnce(const IfaceInfo& iface, SharedState& state, int timeoutMs = 2000);

} // namespace netguard::arpscan
