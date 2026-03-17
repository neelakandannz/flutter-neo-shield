#include "vm_detector.h"

#include <fstream>
#include <string>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include "../shield_codec.h"

#ifdef __x86_64__
#include <cpuid.h>
#endif

namespace flutter_neo_shield {

// Encoded DMI file paths
static const std::string kDmiFiles[] = {
  ShieldCodec::Decode({97,32,49,63,107,45,63,41,63,55,97,55,37,37,107,39,55,103,60,54,33,55,61,47,48,17,61,41,33,33}),  // /sys/class/dmi/id/product_name
  ShieldCodec::Decode({97,32,49,63,107,45,63,41,63,55,97,55,37,37,107,39,55,103,63,61,61,12,62,41,42,42,60,58}),        // /sys/class/dmi/id/sys_vendor
  ShieldCodec::Decode({97,32,49,63,107,45,63,41,63,55,97,55,37,37,107,39,55,103,46,43,47,33,44,19,50,43,61,44,35,54}),  // /sys/class/dmi/id/board_vendor
  ShieldCodec::Decode({97,32,49,63,107,45,63,41,63,55,97,55,37,37,107,39,55,103,46,45,33,32,23,58,33,32,55,39,62}),     // /sys/class/dmi/id/bios_vendor
};
static const size_t kDmiFilesCount = sizeof(kDmiFiles) / sizeof(kDmiFiles[0]);

// Encoded VM identifier strings
static const std::string kVmStrings[] = {
  ShieldCodec::Decode({56,62,63,45,54,43}),                                          // vmware
  ShieldCodec::Decode({56,58,58,56,49,47,63,42,35,60}),                              // virtualbox
  ShieldCodec::Decode({56,49,39,52}),                                                 // vbox
  ShieldCodec::Decode({63,54,37,57}),                                                 // qemu
  ShieldCodec::Decode({37,37,37}),                                                    // kvm
  ShieldCodec::Decode({54,54,38}),                                                    // xen
  ShieldCodec::Decode({62,50,58,45,40,34,54,36,63}),                                 // parallels
  ShieldCodec::Decode({44,59,49,58,33}),                                              // bhyve
  ShieldCodec::Decode({38,42,56,41,54,99,37}),                                       // hyper-v
  ShieldCodec::Decode({35,58,43,62,43,61,60,46,56,100,45,60,58,60,43,60,50,60,37,43,32}), // microsoft corporation
  ShieldCodec::Decode({39,61,38,35,48,43,56}),                                       // innotek
  ShieldCodec::Decode({33,33,41,47,40,43}),                                          // oracle
};
static const size_t kVmStringsCount = sizeof(kVmStrings) / sizeof(kVmStrings[0]);

// Encoded command and result strings
static const std::string kDetectVirtCmd = ShieldCodec::Decode({61,42,59,56,33,35,55,101,40,33,58,54,43,56,105,56,58,58,56,100,124,109,103,40,33,56,124,38,57,40,34}); // systemd-detect-virt 2>/dev/null
static const std::string kNone = ShieldCodec::Decode({32,60,38,41}); // none

bool VMDetector::Check() {
  return CheckCPUID() || CheckDMI() || CheckSystemdDetectVirt();
}

/// Check CPUID hypervisor present bit.
bool VMDetector::CheckCPUID() {
#ifdef __x86_64__
  unsigned int eax, ebx, ecx, edx;
  if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
    return (ecx & (1 << 31)) != 0;
  }
#endif
  return false;
}

/// Check /sys/class/dmi/id for VM identifiers.
bool VMDetector::CheckDMI() {
  for (size_t f = 0; f < kDmiFilesCount; f++) {
    std::ifstream file(kDmiFiles[f]);
    if (!file.is_open()) continue;

    std::string content;
    std::getline(file, content);
    std::transform(content.begin(), content.end(), content.begin(), ::tolower);

    for (size_t v = 0; v < kVmStringsCount; v++) {
      if (content.find(kVmStrings[v]) != std::string::npos) {
        return true;
      }
    }
  }

  return false;
}

/// Use systemd-detect-virt if available.
bool VMDetector::CheckSystemdDetectVirt() {
  FILE* pipe = popen(kDetectVirtCmd.c_str(), "r");
  if (!pipe) return false;

  char buffer[128];
  std::string result;
  while (fgets(buffer, sizeof(buffer), pipe)) {
    result += buffer;
  }

  int status = pclose(pipe);
  if (status == 0 && !result.empty()) {
    // Non-"none" output means virtualization detected
    std::string trimmed = result;
    trimmed.erase(trimmed.find_last_not_of(" \n\r\t") + 1);
    return trimmed != kNone;
  }

  return false;
}

}  // namespace flutter_neo_shield
