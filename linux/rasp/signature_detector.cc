#include "signature_detector.h"

#include <fstream>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <limits.h>
#include "../shield_codec.h"

namespace flutter_neo_shield {

// Encoded strings
static const std::string kProcExe = ShieldCodec::Decode({97,35,58,35,39,97,32,45,32,34,97,54,48,41}); // /proc/self/exe
static const std::string kDangerousVars[] = {
  ShieldCodec::Decode({2,23,23,28,22,11,31,7,13,0}),              // LD_PRELOAD
  ShieldCodec::Decode({2,23,23,0,13,12,1,9,30,29,17,3,9,24,12}),  // LD_LIBRARY_PATH
  ShieldCodec::Decode({2,23,23,13,17,10,26,28}),                   // LD_AUDIT
};
static const size_t kDangerousVarsCount = sizeof(kDangerousVars) / sizeof(kDangerousVars[0]);

bool SignatureDetector::Check() {
  return CheckElfIntegrity() || CheckEnvironment();
}

/// Basic ELF integrity check.
bool SignatureDetector::CheckElfIntegrity() {
  char exe_path[PATH_MAX];
  ssize_t len = readlink(kProcExe.c_str(), exe_path, sizeof(exe_path) - 1);
  if (len == -1) return true;
  exe_path[len] = '\0';

  std::ifstream elf(exe_path, std::ios::binary);
  if (!elf.is_open()) return true;

  // Check ELF magic: 0x7f 'E' 'L' 'F'
  unsigned char magic[4];
  elf.read(reinterpret_cast<char*>(magic), 4);

  if (magic[0] != 0x7F || magic[1] != 'E' ||
      magic[2] != 'L' || magic[3] != 'F') {
    return true;  // Not a valid ELF — tampered
  }

  return false;
}

/// Check for LD injection environment variables.
bool SignatureDetector::CheckEnvironment() {
  for (size_t i = 0; i < kDangerousVarsCount; i++) {
    const char* val = getenv(kDangerousVars[i].c_str());
    if (val && strlen(val) > 0) {
      return true;
    }
  }

  return false;
}

}  // namespace flutter_neo_shield
