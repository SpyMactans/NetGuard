#pragma once
#include <string>

namespace netguard::oui {

// Loads data/oui.txt (format: "AABBCC VendorName" per line) if present,
// in addition to a small built-in table of common vendors. Safe to call
// multiple times; subsequent calls are no-ops.
void load();

// Returns the vendor name for a MAC address's first 3 octets, or
// "Unknown" if not found.
std::string lookup(const std::string& mac);

} // namespace netguard::oui
