#include "port_scan.h"
#include "util.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <cstring>

namespace netguard::portscan {

const std::vector<int> kDefaultPorts = {
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 465, 587, 993, 995, 1723, 3306, 3389,
    5900, 8080, 8443
};

namespace {

bool isPortOpen(const std::string& ip, int port, int timeoutMs) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    // Non-blocking connect with a manual select()-based timeout so one
    // slow/filtered host can't stall the whole scan.
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    bool open = false;
    int rc = connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    if (rc == 0) {
        open = true;
    } else if (errno == EINPROGRESS) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);
        struct timeval tv{};
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        if (select(sock + 1, nullptr, &wfds, nullptr, &tv) > 0) {
            int soError = 0;
            socklen_t len = sizeof(soError);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &soError, &len);
            open = (soError == 0);
        }
    }
    close(sock);
    return open;
}

} // namespace

void scanHost(LanDevice& dev, const std::vector<int>& ports, int perPortTimeoutMs) {
    dev.openPorts.clear();
    for (int port : ports) {
        if (isPortOpen(dev.ip, port, perPortTimeoutMs)) {
            dev.openPorts.push_back(port);
        }
    }
    dev.portsScanned = true;
    if (!dev.openPorts.empty()) {
        util::logToFile("PORT_SCAN host=" + dev.ip + " mac=" + dev.mac +
                         " open=" + std::to_string(dev.openPorts.size()));
    }
}

} // namespace netguard::portscan
