#include "wifi_scan.h"
#include "util.h"

#include <array>
#include <cstdio>
#include <dirent.h>
#include <sstream>
#include <sys/stat.h>

namespace netguard::wifiscan {

namespace {

bool hasWirelessDir(const std::string& ifname) {
    std::string path = "/sys/class/net/" + ifname + "/wireless";
    struct stat st{};
    return stat(path.c_str(), &st) == 0;
}

std::string runCommand(const std::string& cmd) {
    std::array<char, 4096> buffer{};
    std::string result;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return result;
    size_t n;
    while ((n = fread(buffer.data(), 1, buffer.size(), pipe)) > 0) {
        result.append(buffer.data(), n);
    }
    pclose(pipe);
    return result;
}

} // namespace

std::string detectWifiInterface() {
    DIR* d = opendir("/sys/class/net");
    if (!d) return "";
    std::string found;
    struct dirent* entry;
    while ((entry = readdir(d)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;
        if (hasWirelessDir(name)) {
            found = name;
            break;
        }
    }
    closedir(d);
    return found;
}

int scanOnce(const std::string& iface, SharedState& state) {
    if (iface.empty()) return -1;

    std::string cmd = "iw dev " + iface + " scan 2>&1";
    std::string output = runCommand(cmd);
    if (output.find("command not found") != std::string::npos) return -1;
    if (output.find("No such device") != std::string::npos) return -1;

    std::istringstream iss(output);
    std::string line;

    std::string curBssid, curSsid, curSecurity = "Open";
    int curSignal = 0, curChannel = 0;
    bool haveEntry = false;
    int count = 0;

    auto flush = [&]() {
        if (!haveEntry || curBssid.empty()) return;
        std::lock_guard<std::mutex> lock(state.mtx);
        auto it = state.wifiAPs.find(curBssid);
        if (it == state.wifiAPs.end()) {
            WifiAP ap;
            ap.bssid = curBssid;
            ap.ssid = curSsid.empty() ? "<hidden>" : curSsid;
            ap.channel = curChannel;
            ap.signalDbm = curSignal;
            ap.security = curSecurity;
            ap.firstSeen = Clock::now();
            ap.lastSeen = ap.firstSeen;
            ap.trust = TrustState::Unknown;
            state.wifiAPs[curBssid] = ap;
            state.events.push_back({Clock::now(), EventSeverity::Info,
                                     "WiFi AP seen: " + ap.ssid + " (" + curBssid + ")"});
        } else {
            it->second.lastSeen = Clock::now();
            it->second.signalDbm = curSignal;
            it->second.ssid = curSsid.empty() ? it->second.ssid : curSsid;
        }
        ++count;
    };

    while (std::getline(iss, line)) {
        // Each AP entry starts with a line like:
        //   BSS aa:bb:cc:dd:ee:ff(on wlan0)
        if (line.rfind("BSS ", 0) == 0) {
            flush();
            curBssid.clear(); curSsid.clear(); curSecurity = "Open";
            curSignal = 0; curChannel = 0; haveEntry = true;

            size_t start = 4;
            size_t end = line.find('(', start);
            if (end == std::string::npos) end = line.size();
            curBssid = util::normalizeMac(line.substr(start, end - start));
            continue;
        }
        auto trimmed = line;
        size_t firstNonSpace = trimmed.find_first_not_of(" \t");
        if (firstNonSpace != std::string::npos) trimmed = trimmed.substr(firstNonSpace);

        if (trimmed.rfind("SSID:", 0) == 0) {
            curSsid = trimmed.substr(5);
        } else if (trimmed.rfind("signal:", 0) == 0) {
            // "signal: -45.00 dBm"
            try { curSignal = static_cast<int>(std::stod(trimmed.substr(7))); }
            catch (...) {}
        } else if (trimmed.rfind("DS Parameter set: channel", 0) == 0) {
            try { curChannel = std::stoi(trimmed.substr(trimmed.find_last_of(' ') + 1)); }
            catch (...) {}
        } else if (trimmed.find("WPA3") != std::string::npos) {
            curSecurity = "WPA3";
        } else if (trimmed.find("RSN:") != std::string::npos && curSecurity == "Open") {
            curSecurity = "WPA2";
        } else if (trimmed.find("WPA:") != std::string::npos && curSecurity == "Open") {
            curSecurity = "WPA";
        }
    }
    flush();

    if (count > 0) {
        util::logToFile("WIFI_SCAN iface=" + iface + " aps_seen=" + std::to_string(count));
    }
    return count;
}

} // namespace netguard::wifiscan
