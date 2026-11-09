#include "alert.h"
#include <sstream>

namespace netguard::alert {

std::string suggestedLanResponse(const LanDevice& dev) {
    std::ostringstream oss;
    oss << "Suggested operator actions for " << dev.mac << " (" << dev.ip << "):\n"
        << "  1. Verify physically: check the access-controlled area's device log/visitor log.\n"
        << "  2. Switch-level containment: shut the access switch port this host is on\n"
        << "     (e.g. `sudo ifconfig <iface> down` on a managed switch, or via your NAC/\n"
        << "     switch controller's admin panel) rather than attacking the device.\n"
        << "  3. Add to the firewall deny list / VLAN quarantine via your router or\n"
        << "     NAC policy (802.1X / port security), not this tool.\n"
        << "  4. If this is a rogue wireless client, deauthorize it from the AP's own\n"
        << "     admin console (every enterprise AP supports 'disconnect client'\n"
        << "     without affecting other users) instead of broadcasting a jam/deauth.\n"
        << "  5. Escalate to the duty security officer per your SOP.";
    return oss.str();
}

std::string suggestedWifiResponse(const WifiAP& ap) {
    std::ostringstream oss;
    oss << "Suggested operator actions for AP " << ap.bssid << " (\"" << ap.ssid << "\"):\n"
        << "  1. Confirm it isn't a known AP that's simply missing from the baseline\n"
        << "     (approve it if legitimate).\n"
        << "  2. If genuinely rogue, locate it physically via signal strength triangulation\n"
        << "     (walk the area, watch signalDbm rise as you approach).\n"
        << "  3. Report to the network admin / security officer to physically remove it\n"
        << "     or shut its uplink switch port.\n"
        << "  4. Do NOT jam or deauth the channel — that denies service to legitimate\n"
        << "     users too and is illegal to operate without a license in most\n"
        << "     jurisdictions, even on a defence campus.";
    return oss.str();
}

} // namespace netguard::alert
