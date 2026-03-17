#include "debugger_detector.h"

#include <fstream>
#include <string>
#include <unistd.h>
#include "../shield_codec.h"

namespace flutter_neo_shield {

// Encoded strings
static const std::string kProcStatus = ShieldCodec::Decode({97,35,58,35,39,97,32,45,32,34,97,32,60,45,48,59,32});  // /proc/self/status
static const std::string kTracerPid = ShieldCodec::Decode({26,33,41,47,33,60,3,33,40,126});                         // TracerPid:
static const std::string kProcPrefix = ShieldCodec::Decode({97,35,58,35,39,97});                                     // /proc/
static const std::string kComm = ShieldCodec::Decode({97,48,39,33,41});                                              // /comm
static const std::string kDebuggers[] = {
  ShieldCodec::Decode({41,55,42}),           // gdb
  ShieldCodec::Decode({34,63,44,46}),        // lldb
  ShieldCodec::Decode({61,39,58,45,39,43}),  // strace
  ShieldCodec::Decode({34,39,58,45,39,43}),  // ltrace
  ShieldCodec::Decode({42,39,58,57,55,61}),  // dtruss
  ShieldCodec::Decode({56,50,36,43,54,39,61,44}), // valgrind
  ShieldCodec::Decode({60,50,44,45,54,43,97}),     // radare2
  ShieldCodec::Decode({60,97}),              // r2
};
static const size_t kDebuggersCount = sizeof(kDebuggers) / sizeof(kDebuggers[0]);

bool DebuggerDetector::Check() {
  return CheckTracerPid() || CheckParentProcess();
}

/// Read /proc/self/status for TracerPid.
/// Non-zero TracerPid means a debugger (ptrace) is attached.
bool DebuggerDetector::CheckTracerPid() {
  std::ifstream status(kProcStatus);
  if (!status.is_open()) return true;  // fail-closed

  std::string line;
  while (std::getline(status, line)) {
    if (line.compare(0, kTracerPid.size(), kTracerPid) == 0) {
      std::string pid_str = line.substr(kTracerPid.size());
      // Trim whitespace
      size_t start = pid_str.find_first_not_of(" \t");
      if (start != std::string::npos) {
        int pid = std::stoi(pid_str.substr(start));
        return pid != 0;
      }
    }
  }

  return false;
}

/// Check if the parent process is a known debugger.
bool DebuggerDetector::CheckParentProcess() {
  pid_t ppid = getppid();
  std::string comm_path = kProcPrefix + std::to_string(ppid) + kComm;

  std::ifstream comm(comm_path);
  if (!comm.is_open()) return false;

  std::string parent_name;
  std::getline(comm, parent_name);

  for (size_t i = 0; i < kDebuggersCount; i++) {
    if (parent_name.find(kDebuggers[i]) != std::string::npos) {
      return true;
    }
  }

  return false;
}

}  // namespace flutter_neo_shield
