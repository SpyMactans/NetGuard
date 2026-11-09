#include "util.h"
#include <algorithm>
#include <cctype>
#include <ctime>
#include <fstream>
#include <sstream>
#include <unistd.h>

namespace netguard::util {

std::string timeString(TimePoint tp) {
    // Convert steady_clock TimePoint to an offset from "now" so we can
    // print a wall-clock-looking timestamp without mixing clock types.
    auto now = Clock::now();
    auto diff = now - tp;
    auto wallNow = std::chrono::system_clock::now();
    auto wallThen = wallNow - diff;
    std::time_t t = std::chrono::system_clock::to_time_t(wallThen);
    std::tm tmBuf{};
    localtime_r(&t, &tmBuf);
    char buf[16];
    std::strftime(buf, sizeof(buf), "%H:%M:%S", &tmBuf);
    return std::string(buf);
}

std::string normalizeMac(const std::string& raw) {
    std::string hex;
    for (char c : raw) {
        if (std::isxdigit(static_cast<unsigned char>(c))) {
            hex += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
    }
    if (hex.size() != 12) return raw; // not a MAC, return as-is
    std::ostringstream oss;
    for (size_t i = 0; i < 12; i += 2) {
        if (i) oss << ':';
        oss << hex[i] << hex[i + 1];
    }
    return oss.str();
}

void logToFile(const std::string& line) {
    std::ofstream ofs("logs/netguard.log", std::ios::app);
    if (!ofs) return;
    std::time_t t = std::time(nullptr);
    std::tm tmBuf{};
    localtime_r(&t, &tmBuf);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmBuf);
    ofs << "[" << buf << "] " << line << "\n";
}

bool hasRawSocketPrivileges() {
    return geteuid() == 0;
}

} // namespace netguard::util
