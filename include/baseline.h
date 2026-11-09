#pragma once
#include <string>
#include "types.h"

namespace netguard::baseline {

// Loads data/known_lan.txt and data/known_wifi.txt (one MAC/BSSID per
// line, '#' comments allowed) and applies TrustState::Known to any
// already-present entries in `state`. Call again after editing the
// files (e.g. from the dashboard's "approve" action) to refresh.
void loadAndApply(SharedState& state);

// Appends `mac` to data/known_lan.txt so it is trusted on future runs,
// and marks it Known immediately in `state`.
void approveLanDevice(SharedState& state, const std::string& mac);

// Appends `bssid` to data/known_wifi.txt, and marks it Known immediately.
void approveWifiAP(SharedState& state, const std::string& bssid);

// Marks a LAN device Suspicious (operator action from the dashboard).
// This ONLY flags and logs the device for human follow-up — it does
// NOT disconnect, deauthenticate, or otherwise act on the network.
// See alert::suggestedResponse() for the admin actions this should
// prompt a human to take.
void flagLanSuspicious(SharedState& state, const std::string& mac);
void flagWifiSuspicious(SharedState& state, const std::string& bssid);

} // namespace netguard::baseline
