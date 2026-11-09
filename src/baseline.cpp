#include "baseline.h"
#include "util.h"

#include <fstream>
#include <set>

namespace netguard::baseline {

namespace {

std::set<std::string> readList(const std::string& path) {
    std::set<std::string> result;
    std::ifstream f(path);
    if (!f) return result;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        // Allow "mac  # label" trailing comments.
        auto hashPos = line.find('#');
        if (hashPos != std::string::npos) line = line.substr(0, hashPos);
        auto end = line.find_last_not_of(" \t\r\n");
        if (end == std::string::npos) continue;
        line = line.substr(0, end + 1);
        result.insert(util::normalizeMac(line));
    }
    return result;
}

void appendLine(const std::string& path, const std::string& line) {
    std::ofstream f(path, std::ios::app);
    if (f) f << line << "\n";
}

} // namespace

void loadAndApply(SharedState& state) {
    auto knownLan = readList("data/known_lan.txt");
    auto knownWifi = readList("data/known_wifi.txt");

    std::lock_guard<std::mutex> lock(state.mtx);
    for (auto& [mac, dev] : state.lanDevices) {
        if (knownLan.count(mac) && dev.trust != TrustState::Suspicious) {
            dev.trust = TrustState::Known;
        }
    }
    for (auto& [bssid, ap] : state.wifiAPs) {
        if (knownWifi.count(bssid) && ap.trust != TrustState::Suspicious) {
            ap.trust = TrustState::Known;
        }
    }
}

void approveLanDevice(SharedState& state, const std::string& macIn) {
    std::string mac = util::normalizeMac(macIn);
    appendLine("data/known_lan.txt", mac);
    std::lock_guard<std::mutex> lock(state.mtx);
    auto it = state.lanDevices.find(mac);
    if (it != state.lanDevices.end()) {
        it->second.trust = TrustState::Known;
        state.events.push_back({Clock::now(), EventSeverity::Info,
                                 "Approved LAN device " + mac + " as Known"});
    }
}

void approveWifiAP(SharedState& state, const std::string& bssidIn) {
    std::string bssid = util::normalizeMac(bssidIn);
    appendLine("data/known_wifi.txt", bssid);
    std::lock_guard<std::mutex> lock(state.mtx);
    auto it = state.wifiAPs.find(bssid);
    if (it != state.wifiAPs.end()) {
        it->second.trust = TrustState::Known;
        state.events.push_back({Clock::now(), EventSeverity::Info,
                                 "Approved WiFi AP " + bssid + " as Known"});
    }
}

void flagLanSuspicious(SharedState& state, const std::string& macIn) {
    std::string mac = util::normalizeMac(macIn);
    std::lock_guard<std::mutex> lock(state.mtx);
    auto it = state.lanDevices.find(mac);
    if (it == state.lanDevices.end()) return;
    it->second.trust = TrustState::Suspicious;
    state.events.push_back({Clock::now(), EventSeverity::Critical,
                             "OPERATOR FLAGGED SUSPICIOUS: " + mac + " (" + it->second.ip + ")"});
    util::logToFile("FLAG_SUSPICIOUS_LAN mac=" + mac + " ip=" + it->second.ip);
}

void flagWifiSuspicious(SharedState& state, const std::string& bssidIn) {
    std::string bssid = util::normalizeMac(bssidIn);
    std::lock_guard<std::mutex> lock(state.mtx);
    auto it = state.wifiAPs.find(bssid);
    if (it == state.wifiAPs.end()) return;
    it->second.trust = TrustState::Suspicious;
    state.events.push_back({Clock::now(), EventSeverity::Critical,
                             "OPERATOR FLAGGED SUSPICIOUS: AP " + bssid + " (" + it->second.ssid + ")"});
    util::logToFile("FLAG_SUSPICIOUS_WIFI bssid=" + bssid + " ssid=" + it->second.ssid);
}

} // namespace netguard::baseline
