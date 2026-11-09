#pragma once
#include <string>
#include "types.h"

namespace netguard::util {

// Formats a TimePoint as HH:MM:SS relative to wall clock "now".
std::string timeString(TimePoint tp);

// Normalizes a MAC string to lowercase colon-separated form: aa:bb:cc:dd:ee:ff
std::string normalizeMac(const std::string& raw);

// Appends a line to the rotating log file under logs/netguard.log
void logToFile(const std::string& line);

// True if running as root (required for raw sockets / monitor mode).
bool hasRawSocketPrivileges();

} // namespace netguard::util
