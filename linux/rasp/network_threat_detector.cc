#include "network_threat_detector.h"

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <ifaddrs.h>
#include <net/if.h>
#include "../shield_codec.h"

namespace flutter_neo_shield {

// Encoded proxy environment variable names
static const std::string kProxyVars[] = {
  ShieldCodec::Decode({38,39,60,60,27,62,33,39,52,61}),      // http_proxy
  ShieldCodec::Decode({38,39,60,60,55,17,35,58,35,60,55}),   // https_proxy
  ShieldCodec::Decode({6,7,28,28,27,30,1,7,20,29}),          // HTTP_PROXY
  ShieldCodec::Decode({6,7,28,28,23,17,3,26,3,28,23}),       // HTTPS_PROXY
  ShieldCodec::Decode({15,31,4,19,20,28,28,16,21}),          // ALL_PROXY
  ShieldCodec::Decode({47,63,36,19,52,60,60,48,53}),         // all_proxy
};
static const size_t kProxyVarsCount = sizeof(kProxyVars) / sizeof(kProxyVars[0]);

// Encoded VPN interface prefixes
static const std::string kVpnPrefixes[] = {
  ShieldCodec::Decode({58,38,38}),  // tun
  ShieldCodec::Decode({58,50,56}),  // tap
  ShieldCodec::Decode({62,35,56}),  // ppp
  ShieldCodec::Decode({57,52}),     // wg
};
static const size_t kVpnPrefixesCount = sizeof(kVpnPrefixes) / sizeof(kVpnPrefixes[0]);

bool NetworkThreatDetector::CheckSimple() {
  return CheckProxy() || CheckVpn();
}

/// Check for proxy configuration via environment variables.
bool NetworkThreatDetector::CheckProxy() {
  for (size_t i = 0; i < kProxyVarsCount; i++) {
    const char* val = getenv(kProxyVars[i].c_str());
    if (val && strlen(val) > 0) {
      return true;
    }
  }

  return false;
}

/// Check for VPN interfaces via getifaddrs.
bool NetworkThreatDetector::CheckVpn() {
  struct ifaddrs* ifaddr;
  if (getifaddrs(&ifaddr) != 0) return false;

  bool found = false;

  for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
    if (!ifa->ifa_name) continue;

    if (ifa->ifa_flags & IFF_UP) {
      std::string name(ifa->ifa_name);
      for (size_t i = 0; i < kVpnPrefixesCount; i++) {
        if (name.compare(0, kVpnPrefixes[i].size(), kVpnPrefixes[i]) == 0) {
          found = true;
          break;
        }
      }
      if (found) break;
    }
  }

  freeifaddrs(ifaddr);
  return found;
}

}  // namespace flutter_neo_shield
