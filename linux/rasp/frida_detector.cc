#include "frida_detector.h"

#include <fstream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include "../shield_codec.h"

namespace flutter_neo_shield {

// Encoded strings
static const std::string kLocalhost = ShieldCodec::Decode({127,97,127,98,116,96,99,102,125});  // 127.0.0.1
static const std::string kProcMaps = ShieldCodec::Decode({97,35,58,35,39,97,32,45,32,34,97,62,41,60,55}); // /proc/self/maps
static const std::string kFrida = ShieldCodec::Decode({40,33,33,40,37});           // frida
static const std::string kLinjector = ShieldCodec::Decode({34,58,38,38,33,45,39,39,62}); // linjector
static const std::string kFridaPaths[] = {
  ShieldCodec::Decode({97,38,59,62,107,44,58,38,99,34,60,58,44,45,105,61,54,58,58,33,60}),                     // /usr/bin/frida-server
  ShieldCodec::Decode({97,38,59,62,107,34,60,43,45,40,97,49,33,34,107,40,33,33,40,37,99,32,45,62,50,43,33}),   // /usr/local/bin/frida-server
  ShieldCodec::Decode({97,38,59,62,107,34,60,43,45,40,97,49,33,34,107,40,33,33,40,37}),                         // /usr/local/bin/frida
  ShieldCodec::Decode({97,39,37,60,107,40,33,33,40,37,99,32,45,62,50,43,33}),                                   // /tmp/frida-server
};
static const size_t kFridaPathsCount = sizeof(kFridaPaths) / sizeof(kFridaPaths[0]);

bool FridaDetector::Check() {
  return CheckPorts() || CheckMaps() || CheckFiles();
}

/// Scan Frida default ports on localhost.
bool FridaDetector::CheckPorts() {
  int ports[] = {27042, 27043, 4444};

  for (int port : ports) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) continue;

    // Set non-blocking with timeout
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(kLocalhost.c_str());

    int result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    close(sock);

    if (result == 0) return true;
  }

  return false;
}

/// Scan /proc/self/maps for frida-agent and frida-gadget.
bool FridaDetector::CheckMaps() {
  std::ifstream maps(kProcMaps);
  if (!maps.is_open()) return true;  // Fail-closed: can't read maps

  std::string line;
  while (std::getline(maps, line)) {
    if (line.find(kFrida) != std::string::npos ||
        line.find(kLinjector) != std::string::npos) {
      return true;
    }
  }

  return false;
}

/// Check for frida-server binaries.
bool FridaDetector::CheckFiles() {
  for (size_t i = 0; i < kFridaPathsCount; i++) {
    if (access(kFridaPaths[i].c_str(), F_OK) == 0) {
      return true;
    }
  }

  return false;
}

}  // namespace flutter_neo_shield
