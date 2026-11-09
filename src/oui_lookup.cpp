#include "oui_lookup.h"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <unordered_map>

namespace netguard::oui {

namespace {

std::unordered_map<std::string, std::string>& table() {
    static std::unordered_map<std::string, std::string> t;
    return t;
}

bool& loaded() {
    static bool l = false;
    return l;
}

std::string prefixOf(const std::string& mac) {
    std::string hex;
    for (char c : mac) {
        if (std::isxdigit(static_cast<unsigned char>(c))) {
            hex += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
    }
    if (hex.size() < 6) return "";
    return hex.substr(0, 6);
}

// A small built-in set of common vendor OUIs so the tool is useful even
// without internet access to fetch the full IEEE registry.
void loadBuiltins() {
    static const std::pair<const char*, const char*> builtins[] = {
        {"001A11", "Google"},
        {"3C5AB4", "Google"},
        {"F4F5D8", "Google"},
        {"000C29", "VMware"},
        {"005056", "VMware"},
        {"001C42", "Parallels"},
        {"08002B", "DEC"},
        {"001B63", "Apple"},
        {"F0DBF8", "Apple"},
        {"A4C361", "Apple"},
        {"3C0754", "Apple"},
        {"DCA632", "Raspberry Pi Foundation"},
        {"B827EB", "Raspberry Pi Foundation"},
        {"E45F01", "Raspberry Pi Foundation"},
        {"000D93", "Apple"},
        {"001E58", "WistronNeweb"},
        {"7CD1C3", "Intel"},
        {"3CA9F4", "Intel"},
        {"B4B686", "Intel"},
        {"9C5C8E", "Dell"},
        {"D4BED9", "Dell"},
        {"001517", "Cisco-Linksys"},
        {"0023EB", "Cisco"},
        {"E89F80", "Hon Hai (Foxconn)"},
        {"ACDE48", "Private/Randomized"},
        {"000000", "Xerox"},
        {"005018", "ASRock"},
        {"08001F", "Huawei"},
        {"F83DFF", "Huawei"},
        {"BCF5AC", "TP-Link"},
        {"C46E1F", "TP-Link"},
        {"50C7BF", "TP-Link"},
        {"001D73", "Netgear"},
        {"204E71", "Netgear"},
        {"0024A5", "Buffalo"},
        {"D45D64", "Samsung"},
        {"E8508B", "Samsung"},
        {"5C0A5B", "Samsung"},
        {"A0CDF3", "Samsung"},
    };
    for (auto& [prefix, vendor] : builtins) {
        table()[prefix] = vendor;
    }
}

void loadFile() {
    std::ifstream f("data/oui.txt");
    if (!f) return;
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string prefix, vendor;
        if (!(iss >> prefix)) continue;
        std::getline(iss, vendor);
        // trim leading space
        size_t start = vendor.find_first_not_of(" \t");
        if (start == std::string::npos) continue;
        vendor = vendor.substr(start);
        std::transform(prefix.begin(), prefix.end(), prefix.begin(), ::toupper);
        table()[prefix] = vendor;
    }
}

} // namespace

void load() {
    if (loaded()) return;
    loadBuiltins();
    loadFile();
    loaded() = true;
}

std::string lookup(const std::string& mac) {
    load();
    auto prefix = prefixOf(mac);
    auto it = table().find(prefix);
    if (it == table().end()) return "Unknown";
    return it->second;
}

} // namespace netguard::oui
