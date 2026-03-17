#include "native_debug_detector.h"

#include <fstream>
#include <string>
#include <chrono>
#include <sys/ptrace.h>
#include <errno.h>
#include "../shield_codec.h"

namespace flutter_neo_shield {

// Encoded strings
static const std::string kProcStatus = ShieldCodec::Decode({97,35,58,35,39,97,32,45,32,34,97,32,60,45,48,59,32}); // /proc/self/status
static const std::string kTracerPid = ShieldCodec::Decode({26,33,41,47,33,60,3,33,40,126});                        // TracerPid:
static const std::string kProcWchan = ShieldCodec::Decode({97,35,58,35,39,97,32,45,32,34,97,36,43,36,37,32});     // /proc/self/wchan
static const std::string kPtrace = ShieldCodec::Decode({62,39,58,45,39,43});   // ptrace
static const std::string kTrace = ShieldCodec::Decode({58,33,41,47,33});       // trace

bool NativeDebugDetector::Check() {
  return CheckTracerPid() ||
         CheckPtrace() ||
         CheckWchan() ||
         CheckTimingAnomaly();
}

/// Read /proc/self/status TracerPid.
bool NativeDebugDetector::CheckTracerPid() {
  std::ifstream status(kProcStatus);
  if (!status.is_open()) return true;

  std::string line;
  while (std::getline(status, line)) {
    if (line.compare(0, kTracerPid.size(), kTracerPid) == 0) {
      std::string pid_str = line.substr(kTracerPid.size());
      size_t start = pid_str.find_first_not_of(" \t");
      if (start != std::string::npos) {
        int pid = std::stoi(pid_str.substr(start));
        return pid != 0;
      }
    }
  }

  return false;
}

/// Try PTRACE_TRACEME to detect if we're already being traced.
bool NativeDebugDetector::CheckPtrace() {
  long result = ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
  if (result == -1) {
    if (errno == EPERM) {
      return true;  // Already being traced
    }
  } else {
    // Successfully traced ourselves — detach
    ptrace(PTRACE_DETACH, 0, nullptr, nullptr);
  }
  return false;
}

/// Check /proc/self/wchan for ptrace-related wait.
bool NativeDebugDetector::CheckWchan() {
  std::ifstream wchan(kProcWchan);
  if (!wchan.is_open()) return false;

  std::string content;
  std::getline(wchan, content);

  if (content.find(kPtrace) != std::string::npos ||
      content.find(kTrace) != std::string::npos) {
    return true;
  }

  return false;
}

/// Timing-based detection.
bool NativeDebugDetector::CheckTimingAnomaly() {
  auto start = std::chrono::high_resolution_clock::now();

  volatile int sum = 0;
  for (int i = 0; i < 10000; i++) {
    sum += i;
  }

  auto end = std::chrono::high_resolution_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

  return elapsed.count() > 500;
}

}  // namespace flutter_neo_shield
