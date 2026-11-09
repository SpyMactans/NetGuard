#pragma once
#include <string>
#include <vector>
#include <chrono>
#include <mutex>
#include <map>

namespace netguard {

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

// ---------------------------------------------------------------------
// Trust / threat classification for a seen device.
// A device starts Unknown, gets promoted to Known once an operator
// approves it (added to the baseline file), or can be hand-flagged
// Suspicious by an operator via the dashboard.
// ---------------------------------------------------------------------
enum class TrustState {
    Known,       // present in the baseline file, approved
    Unknown,     // seen on the network but not in baseline -> alert
    Suspicious   // operator has manually flagged this device
};

std::string toString(TrustState s);

// ---------------------------------------------------------------------
// A host discovered on the local (Ethernet/WiFi-associated) LAN segment
// ---------------------------------------------------------------------
struct LanDevice {
    std::string ip;
    std::string mac;
    std::string vendor;        // resolved from OUI prefix
    std::string hostname;      // best-effort reverse DNS / NetBIOS
    TrustState  trust = TrustState::Unknown;
    TimePoint   firstSeen;
    TimePoint   lastSeen;
    std::vector<int> openPorts;
    bool portsScanned = false;
};

// ---------------------------------------------------------------------
// A WiFi access point observed via passive (monitor-mode / iw) scanning.
// No frames are transmitted toward it — this is listen-only.
// ---------------------------------------------------------------------
struct WifiAP {
    std::string ssid;
    std::string bssid;
    int channel = 0;
    int signalDbm = 0;
    std::string security;      // e.g. WPA2, WPA3, Open
    TrustState  trust = TrustState::Unknown;
    TimePoint   firstSeen;
    TimePoint   lastSeen;
};

// ---------------------------------------------------------------------
// A log-worthy event for the alert feed / audit trail
// ---------------------------------------------------------------------
enum class EventSeverity { Info, Warning, Critical };

struct Event {
    TimePoint time;
    EventSeverity severity;
    std::string message;
};

// Thread-safe shared state the scanner threads publish into and the
// dashboard thread reads from.
struct SharedState {
    std::mutex mtx;
    std::map<std::string, LanDevice> lanDevices;   // keyed by MAC
    std::map<std::string, WifiAP> wifiAPs;         // keyed by BSSID
    std::vector<Event> events;
    bool running = true;
};

} // namespace netguard
