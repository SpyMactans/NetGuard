#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <vector>

#include "types.h"
#include "util.h"
#include "oui_lookup.h"
#include "arp_scan.h"
#include "port_scan.h"
#include "wifi_scan.h"
#include "baseline.h"
#include "dashboard.h"

using namespace netguard;

namespace {

void lanScanLoop(SharedState& state, const arpscan::IfaceInfo& iface) {
    while (true) {
        {
            std::lock_guard<std::mutex> lock(state.mtx);
            if (!state.running) return;
        }
        arpscan::sweepOnce(iface, state, 2000);
        baseline::loadAndApply(state);
        std::this_thread::sleep_for(std::chrono::seconds(8));
    }
}

void wifiScanLoop(SharedState& state, const std::string& iface) {
    if (iface.empty()) return;
    while (true) {
        {
            std::lock_guard<std::mutex> lock(state.mtx);
            if (!state.running) return;
        }
        wifiscan::scanOnce(iface, state);
        baseline::loadAndApply(state);
        std::this_thread::sleep_for(std::chrono::seconds(15));
    }
}

void portScanLoop(SharedState& state) {
    while (true) {
        {
            std::lock_guard<std::mutex> lock(state.mtx);
            if (!state.running) return;
        }
        // Find one device that still needs scanning, copy it out, scan
        // outside the lock, then write results back.
        std::string targetMac;
        LanDevice snapshot;
        {
            std::lock_guard<std::mutex> lock(state.mtx);
            for (auto& [mac, dev] : state.lanDevices) {
                if (!dev.portsScanned) {
                    targetMac = mac;
                    snapshot = dev;
                    break;
                }
            }
        }
        if (!targetMac.empty()) {
            portscan::scanHost(snapshot, portscan::kDefaultPorts);
            std::lock_guard<std::mutex> lock(state.mtx);
            auto it = state.lanDevices.find(targetMac);
            if (it != state.lanDevices.end()) {
                it->second.openPorts = snapshot.openPorts;
                it->second.portsScanned = true;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
}

} // namespace

int main(int argc, char** argv) {
    std::signal(SIGPIPE, SIG_IGN);

    std::string preferredIface;
    if (argc > 1) preferredIface = argv[1];

    if (!util::hasRawSocketPrivileges()) {
        std::fprintf(stderr,
            "netguard: this tool needs raw-socket privileges to send ARP\n"
            "requests and trigger WiFi scans. Run with sudo, e.g.:\n"
            "  sudo ./netguard [interface]\n");
        return 1;
    }

    oui::load();

    arpscan::IfaceInfo iface = arpscan::detectInterface(preferredIface);
    if (!iface.valid) {
        std::fprintf(stderr, "netguard: no usable network interface found.\n");
        return 1;
    }
    std::string wifiIface = wifiscan::detectWifiInterface();

    SharedState state;
    state.events.push_back({Clock::now(), EventSeverity::Info,
        "netguard started on " + iface.name + " (" + iface.ipStr + ")"});

    std::vector<std::thread> workers;
    workers.emplace_back(lanScanLoop, std::ref(state), iface);
    workers.emplace_back(wifiScanLoop, std::ref(state), wifiIface);
    workers.emplace_back(portScanLoop, std::ref(state));

    // Dashboard owns the terminal and runs on the main thread.
    dashboard::run(state);

    {
        std::lock_guard<std::mutex> lock(state.mtx);
        state.running = false;
    }
    for (auto& t : workers) {
        if (t.joinable()) t.join();
    }

    std::printf("netguard: shut down cleanly. See logs/netguard.log for the audit trail.\n");
    return 0;
}
