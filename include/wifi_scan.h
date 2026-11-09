#pragma once
#include <string>
#include "types.h"

namespace netguard::wifiscan {

// Finds a wireless interface name (e.g. "wlan0") by checking /sys/class/net
// for a "wireless" subdirectory. Returns "" if none found.
std::string detectWifiInterface();

// Runs one scan cycle via the standard `iw dev <iface> scan` command
// (the same mechanism any OS uses to list nearby networks — a standard
// probe-request scan, not monitor-mode sniffing or packet injection).
// Parses the output and merges results into `state`.
// Requires CAP_NET_ADMIN (root) because triggering a scan does.
//
// Returns the number of APs seen in this cycle, or -1 on failure
// (e.g. `iw` not installed, or no wireless interface).
int scanOnce(const std::string& iface, SharedState& state);

} // namespace netguard::wifiscan
