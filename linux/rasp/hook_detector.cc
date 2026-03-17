#include "hook_detector.h"

#include <cstdlib>
#include <fstream>
#include <string>
#include "../shield_codec.h"

namespace flutter_neo_shield {

// Encoded strings
static const std::string kLdPreload = ShieldCodec::Decode({2,23,23,28,22,11,31,7,13,0});             // LD_PRELOAD
static const std::string kEtcPreload = ShieldCodec::Decode({97,54,60,47,107,34,55,102,63,43,96,35,58,41,40,33,50,44}); // /etc/ld.so.preload
static const std::string kProcMaps = ShieldCodec::Decode({97,35,58,35,39,97,32,45,32,34,97,62,41,60,55}); // /proc/self/maps
static const std::string kSuspicious[] = {
  ShieldCodec::Decode({61,38,42,63,48,60,50,60,41}),  // substrate
  ShieldCodec::Decode({39,61,34,41,39,58}),            // inject
  ShieldCodec::Decode({38,60,39,39}),                  // hook
  ShieldCodec::Decode({39,61,60,41,54,62,60,59,41}),   // interpose
  ShieldCodec::Decode({40,33,33,40,37}),               // frida
  ShieldCodec::Decode({45,42,43,62,45,62,39}),         // cycript
  ShieldCodec::Decode({54,35,39,63,33,42}),            // xposed
};
static const size_t kSuspiciousCount = sizeof(kSuspicious) / sizeof(kSuspicious[0]);

bool HookDetector::Check() {
  return CheckLDPreload() || CheckMaps();
}

/// Check LD_PRELOAD environment variable.
bool HookDetector::CheckLDPreload() {
  const char* ld_preload = getenv(kLdPreload.c_str());
  if (ld_preload && strlen(ld_preload) > 0) {
    return true;
  }

  // Also check /etc/ld.so.preload
  std::ifstream preload(kEtcPreload);
  if (preload.is_open()) {
    std::string line;
    while (std::getline(preload, line)) {
      // Skip empty lines and comments
      if (!line.empty() && line[0] != '#') {
        return true;
      }
    }
  }

  return false;
}

/// Scan /proc/self/maps for suspicious shared libraries.
bool HookDetector::CheckMaps() {
  std::ifstream maps(kProcMaps);
  if (!maps.is_open()) return true;  // Fail-closed: can't read maps

  std::string line;
  while (std::getline(maps, line)) {
    for (size_t i = 0; i < kSuspiciousCount; i++) {
      if (line.find(kSuspicious[i]) != std::string::npos) {
        return true;
      }
    }
  }

  return false;
}

}  // namespace flutter_neo_shield
