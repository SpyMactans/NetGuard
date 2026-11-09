#include "arp_scan.h"
#include "util.h"
#include "oui_lookup.h"

#include <cstring>
#include <cstdio>
#include <vector>
#include <map>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <pcap/pcap.h>

namespace netguard::arpscan {

namespace {

#pragma pack(push, 1)
struct ArpPacket {
    // Ethernet header
    uint8_t  dstMac[6];
    uint8_t  srcMac[6];
    uint16_t etherType;
    // ARP header
    uint16_t htype;
    uint16_t ptype;
    uint8_t  hlen;
    uint8_t  plen;
    uint16_t oper;
    uint8_t  senderMac[6];
    uint8_t  senderIp[4];
    uint8_t  targetMac[6];
    uint8_t  targetIp[4];
};
#pragma pack(pop)

std::string macToStr(const uint8_t* m) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                  m[0], m[1], m[2], m[3], m[4], m[5]);
    return buf;
}

std::string ipToStr(const uint8_t* ip) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return buf;
}

} // namespace

IfaceInfo detectInterface(const std::string& preferredName) {
    IfaceInfo result;
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) != 0) return result;

    // First pass: find IPv4 address + netmask for the chosen/first candidate iface.
    for (auto* ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        if (!(ifa->ifa_flags & IFF_UP)) continue;

        std::string name = ifa->ifa_name;
        if (!preferredName.empty() && name != preferredName) continue;

        auto* sin = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
        auto* mask = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_netmask);

        result.name = name;
        result.ip = ntohl(sin->sin_addr.s_addr);
        result.netmask = ntohl(mask->sin_addr.s_addr);
        char ipbuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf));
        result.ipStr = ipbuf;
        result.valid = true;
        break;
    }
    freeifaddrs(ifaddr);
    if (!result.valid) return result;

    // Get the interface's own MAC address via a UDP socket + ioctl.
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
        struct ifreq ifr{};
        std::strncpy(ifr.ifr_name, result.name.c_str(), IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
            result.macStr = macToStr(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));
        }
        close(sock);
    }
    return result;
}

int sweepOnce(const IfaceInfo& iface, SharedState& state, int timeoutMs) {
    if (!iface.valid || iface.macStr.empty()) return 0;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface.name.c_str(), 65536, 1, 10, errbuf);
    if (!handle) {
        util::logToFile(std::string("pcap_open_live failed: ") + errbuf);
        return 0;
    }
    // Only look at ARP replies.
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "arp", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(handle, &fp);
        pcap_freecode(&fp);
    }

    uint32_t network = iface.ip & iface.netmask;
    uint32_t broadcast = network | ~iface.netmask;
    uint32_t hostCount = broadcast - network;
    // Guard against scanning something absurd (e.g. misdetected /8).
    if (hostCount == 0 || hostCount > 1024) hostCount = 254; // fall back to /24-sized sweep

    uint8_t srcMacBytes[6]{};
    {
        unsigned vals[6];
        std::sscanf(iface.macStr.c_str(), "%x:%x:%x:%x:%x:%x",
                    &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]);
        for (int i = 0; i < 6; ++i) srcMacBytes[i] = static_cast<uint8_t>(vals[i]);
    }

    // Send ARP "who-has" requests to every host in the subnet.
    for (uint32_t offset = 1; offset < hostCount; ++offset) {
        uint32_t targetIp = network + offset;
        if (targetIp == iface.ip) continue; // skip ourselves

        ArpPacket pkt{};
        std::memset(pkt.dstMac, 0xff, 6); // broadcast
        std::memcpy(pkt.srcMac, srcMacBytes, 6);
        pkt.etherType = htons(ETHERTYPE_ARP);
        pkt.htype = htons(1);       // Ethernet
        pkt.ptype = htons(ETHERTYPE_IP);
        pkt.hlen = 6;
        pkt.plen = 4;
        pkt.oper = htons(1);        // ARP request
        std::memcpy(pkt.senderMac, srcMacBytes, 6);
        uint32_t ipNet = htonl(iface.ip);
        std::memcpy(pkt.senderIp, &ipNet, 4);
        std::memset(pkt.targetMac, 0x00, 6);
        uint32_t tNet = htonl(targetIp);
        std::memcpy(pkt.targetIp, &tNet, 4);

        pcap_sendpacket(handle, reinterpret_cast<u_char*>(&pkt), sizeof(pkt));
    }

    // Listen for replies until the timeout elapses.
    int seen = 0;
    auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
    pcap_set_timeout(handle, 50);

    while (Clock::now() < deadline) {
        struct pcap_pkthdr* header;
        const u_char* data;
        int rc = pcap_next_ex(handle, &header, &data);
        if (rc != 1) continue; // timeout / no packet this tick

        if (header->caplen < sizeof(ArpPacket)) continue;
        auto* arp = reinterpret_cast<const ArpPacket*>(data);
        if (ntohs(arp->etherType) != ETHERTYPE_ARP) continue;
        if (ntohs(arp->oper) != 2) continue; // only replies

        std::string mac = util::normalizeMac(macToStr(arp->senderMac));
        std::string ip = ipToStr(arp->senderIp);
        if (mac == "00:00:00:00:00:00") continue;

        std::lock_guard<std::mutex> lock(state.mtx);
        auto it = state.lanDevices.find(mac);
        if (it == state.lanDevices.end()) {
            LanDevice dev;
            dev.mac = mac;
            dev.ip = ip;
            dev.vendor = oui::lookup(mac);
            dev.firstSeen = Clock::now();
            dev.lastSeen = dev.firstSeen;
            dev.trust = TrustState::Unknown;
            state.lanDevices[mac] = dev;
            state.events.push_back({Clock::now(), EventSeverity::Warning,
                                     "New LAN device: " + mac + " (" + ip + ", " + dev.vendor + ")"});
            util::logToFile("NEW_LAN_DEVICE mac=" + mac + " ip=" + ip + " vendor=" + dev.vendor);
        } else {
            it->second.ip = ip;
            it->second.lastSeen = Clock::now();
        }
        ++seen;
    }

    pcap_close(handle);
    return seen;
}

} // namespace netguard::arpscan
