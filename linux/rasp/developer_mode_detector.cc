#include "developer_mode_detector.h"

#include <fstream>
#include <string>
#include <unistd.h>
#include "../shield_codec.h"

namespace flutter_neo_shield {

// Encoded strings
static const std::string kPtraceScope = ShieldCodec::Decode({97,35,58,35,39,97,32,49,63,107,37,54,58,34,33,34,124,49,45,41,47,124,56,56,54,47,48,45,19,55,45,60,56,41}); // /proc/sys/kernel/yama/ptrace_scope
static const std::string kToolPaths[] = {
  ShieldCodec::Decode({97,38,59,62,107,44,58,38,99,35,42,49}),                 // /usr/bin/gdb
  ShieldCodec::Decode({97,38,59,62,107,44,58,38,99,55,58,33,41,47,33}),        // /usr/bin/strace
  ShieldCodec::Decode({97,38,59,62,107,44,58,38,99,40,58,33,41,47,33}),        // /usr/bin/ltrace
  ShieldCodec::Decode({97,38,59,62,107,44,58,38,99,50,47,63,47,62,45,32,55}),  // /usr/bin/valgrind
  ShieldCodec::Decode({97,38,59,62,107,44,58,38,99,54,47,55,41,62,33,124}),    // /usr/bin/radare2
  ShieldCodec::Decode({97,38,59,62,107,44,58,38,99,54,124}),                    // /usr/bin/r2
};
static const size_t kToolPathsCount = sizeof(kToolPaths) / sizeof(kToolPaths[0]);

bool DeveloperModeDetector::Check() {
  return CheckPtraceScope() || CheckDevToolsInstalled();
}

/// Check kernel.yama.ptrace_scope.
bool DeveloperModeDetector::CheckPtraceScope() {
  std::ifstream f(kPtraceScope);
  if (!f.is_open()) return false;

  int scope = -1;
  f >> scope;

  return scope == 0;
}

/// Check if common debugging tools are installed.
bool DeveloperModeDetector::CheckDevToolsInstalled() {
  for (size_t i = 0; i < kToolPathsCount; i++) {
    if (access(kToolPaths[i].c_str(), X_OK) == 0) {
      return true;
    }
  }

  return false;
}

}  // namespace flutter_neo_shield
