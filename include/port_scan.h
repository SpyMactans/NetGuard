#pragma once
#include "types.h"

namespace netguard::portscan {

// A small, representative set of commonly-interesting ports. Kept short
// so a scan stays fast for a live dashboard; extend as needed for a
// fuller audit.
extern const std::vector<int> kDefaultPorts;

// Runs a TCP connect() scan of `dev`'s IP against `ports`, with a short
// per-port timeout. Populates dev.openPorts and sets dev.portsScanned.
// This is a standard, non-stealth connect scan (completes the TCP
// handshake), equivalent to `nmap -sT`.
void scanHost(LanDevice& dev, const std::vector<int>& ports, int perPortTimeoutMs = 150);

} // namespace netguard::portscan
