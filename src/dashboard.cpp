#include "dashboard.h"
#include "baseline.h"
#include "alert.h"
#include "util.h"

#include <ncurses.h>
#include <vector>
#include <string>
#include <algorithm>

namespace netguard::dashboard {

namespace {

enum class Panel { Lan, Wifi };

const char* trustLabel(TrustState s) {
    switch (s) {
        case TrustState::Known: return "KNOWN";
        case TrustState::Unknown: return "UNKNOWN";
        case TrustState::Suspicious: return "SUSPICIOUS";
    }
    return "?";
}

int trustColorPair(TrustState s) {
    switch (s) {
        case TrustState::Known: return 1;      // green
        case TrustState::Unknown: return 2;    // yellow
        case TrustState::Suspicious: return 3; // red
    }
    return 0;
}

void drawHeader(int width) {
    attron(COLOR_PAIR(4) | A_BOLD);
    mvhline(0, 0, ' ', width);
    mvprintw(0, 1, "NetGuard — LAN/WiFi Monitoring Dashboard (FYP build)");
    attroff(COLOR_PAIR(4) | A_BOLD);
}

void drawFooter(int height, int width, Panel active) {
    std::string hint = "[Tab] switch LAN/WiFi  [Up/Down] select  [a] approve known  "
                        "[s] flag suspicious  [p] port-scan  [q] quit";
    attron(COLOR_PAIR(4));
    mvhline(height - 1, 0, ' ', width);
    mvprintw(height - 1, 1, "%s", hint.c_str());
    (void)active;
    attroff(COLOR_PAIR(4));
}

} // namespace

void run(SharedState& state) {
    initscr();
    start_color();
    use_default_colors();
    cbreak();
    noecho();
    curs_set(0);
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE); // non-blocking getch so the UI keeps refreshing

    init_pair(1, COLOR_GREEN, -1);
    init_pair(2, COLOR_YELLOW, -1);
    init_pair(3, COLOR_RED, -1);
    init_pair(4, COLOR_BLACK, COLOR_CYAN);
    init_pair(5, COLOR_WHITE, COLOR_BLUE); // selected row

    Panel active = Panel::Lan;
    int lanSel = 0, wifiSel = 0;
    std::string statusMsg;

    while (true) {
        {
            std::lock_guard<std::mutex> lock(state.mtx);
            if (!state.running) break;
        }

        int height, width;
        getmaxyx(stdscr, height, width);
        erase();
        drawHeader(width);

        int lanRows = (height - 4) / 2;
        int wifiRowsStart = 3 + lanRows + 1;

        std::vector<LanDevice> lanList;
        std::vector<WifiAP> wifiList;
        {
            std::lock_guard<std::mutex> lock(state.mtx);
            for (auto& [mac, d] : state.lanDevices) lanList.push_back(d);
            for (auto& [b, a] : state.wifiAPs) wifiList.push_back(a);
        }
        std::sort(lanList.begin(), lanList.end(), [](auto& a, auto& b) { return a.ip < b.ip; });
        std::sort(wifiList.begin(), wifiList.end(),
                  [](auto& a, auto& b) { return a.signalDbm > b.signalDbm; });

        // --- LAN panel ---
        attron(A_BOLD);
        mvprintw(2, 1, "LAN DEVICES (%zu)", lanList.size());
        attroff(A_BOLD);
        mvprintw(3, 1, "%-16s %-18s %-10s %-20s %-10s %s",
                 "IP", "MAC", "TRUST", "VENDOR", "PORTS", "HOSTNAME");
        for (int i = 0; i < (int)lanList.size() && i < lanRows - 1; ++i) {
            auto& d = lanList[i];
            bool sel = (active == Panel::Lan && i == lanSel);
            if (sel) attron(COLOR_PAIR(5));
            std::string portsStr = d.portsScanned
                ? std::to_string(d.openPorts.size()) + " open"
                : "-";
            mvprintw(4 + i, 1, "%-16s %-18s ", d.ip.c_str(), d.mac.c_str());
            if (!sel) attron(COLOR_PAIR(trustColorPair(d.trust)));
            printw("%-10s", trustLabel(d.trust));
            if (!sel) attroff(COLOR_PAIR(trustColorPair(d.trust)));
            printw(" %-20s %-10s %s", d.vendor.c_str(), portsStr.c_str(), d.hostname.c_str());
            if (sel) attroff(COLOR_PAIR(5));
        }

        // --- WiFi panel ---
        attron(A_BOLD);
        mvprintw(wifiRowsStart - 1, 1, "WIFI ACCESS POINTS (%zu)", wifiList.size());
        attroff(A_BOLD);
        mvprintw(wifiRowsStart, 1, "%-20s %-18s %-6s %-8s %-10s %s",
                 "SSID", "BSSID", "CHAN", "SIGNAL", "TRUST", "SECURITY");
        int wifiRows = height - wifiRowsStart - 2;
        for (int i = 0; i < (int)wifiList.size() && i < wifiRows - 1; ++i) {
            auto& a = wifiList[i];
            bool sel = (active == Panel::Wifi && i == wifiSel);
            if (sel) attron(COLOR_PAIR(5));
            mvprintw(wifiRowsStart + 1 + i, 1, "%-20.20s %-18s %-6d %-8d ",
                      a.ssid.c_str(), a.bssid.c_str(), a.channel, a.signalDbm);
            if (!sel) attron(COLOR_PAIR(trustColorPair(a.trust)));
            printw("%-10s", trustLabel(a.trust));
            if (!sel) attroff(COLOR_PAIR(trustColorPair(a.trust)));
            printw(" %s", a.security.c_str());
            if (sel) attroff(COLOR_PAIR(5));
        }

        if (!statusMsg.empty()) {
            attron(COLOR_PAIR(2) | A_BOLD);
            mvprintw(height - 2, 1, "%.*s", width - 2, statusMsg.c_str());
            attroff(COLOR_PAIR(2) | A_BOLD);
        }

        drawFooter(height, width, active);
        refresh();

        int ch = getch();
        if (ch == 'q' || ch == 'Q') {
            std::lock_guard<std::mutex> lock(state.mtx);
            state.running = false;
            break;
        } else if (ch == '\t') {
            active = (active == Panel::Lan) ? Panel::Wifi : Panel::Lan;
        } else if (ch == KEY_UP) {
            if (active == Panel::Lan) lanSel = std::max(0, lanSel - 1);
            else wifiSel = std::max(0, wifiSel - 1);
        } else if (ch == KEY_DOWN) {
            if (active == Panel::Lan) lanSel = std::min((int)lanList.size() - 1, lanSel + 1);
            else wifiSel = std::min((int)wifiList.size() - 1, wifiSel + 1);
        } else if (ch == 'a' || ch == 'A') {
            if (active == Panel::Lan && lanSel < (int)lanList.size()) {
                baseline::approveLanDevice(state, lanList[lanSel].mac);
                statusMsg = "Approved " + lanList[lanSel].mac + " as known.";
            } else if (active == Panel::Wifi && wifiSel < (int)wifiList.size()) {
                baseline::approveWifiAP(state, wifiList[wifiSel].bssid);
                statusMsg = "Approved " + wifiList[wifiSel].bssid + " as known.";
            }
        } else if (ch == 's' || ch == 'S') {
            if (active == Panel::Lan && lanSel < (int)lanList.size()) {
                baseline::flagLanSuspicious(state, lanList[lanSel].mac);
                statusMsg = alert::suggestedLanResponse(lanList[lanSel]);
            } else if (active == Panel::Wifi && wifiSel < (int)wifiList.size()) {
                baseline::flagWifiSuspicious(state, wifiList[wifiSel].bssid);
                statusMsg = alert::suggestedWifiResponse(wifiList[wifiSel]);
            }
        } else if (ch == 'p' || ch == 'P') {
            if (active == Panel::Lan && lanSel < (int)lanList.size()) {
                statusMsg = "Port-scanning " + lanList[lanSel].ip + " ... (runs in background)";
                // Actual scan dispatched by main's worker thread; here we
                // just mark it requested via a simple flag in the map.
                std::lock_guard<std::mutex> lock(state.mtx);
                auto it = state.lanDevices.find(lanList[lanSel].mac);
                if (it != state.lanDevices.end()) it->second.portsScanned = false;
            }
        }

        napms(100);
    }

    endwin();
}

} // namespace netguard::dashboard
