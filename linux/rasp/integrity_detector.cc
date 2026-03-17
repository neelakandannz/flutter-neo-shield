#include "integrity_detector.h"

#include <fstream>
#include <string>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#include "../shield_codec.h"

namespace flutter_neo_shield {

// Encoded strings
static const std::string kProcExe = ShieldCodec::Decode({97,35,58,35,39,97,32,45,32,34,97,54,48,41}); // /proc/self/exe
static const std::string kDeleted = ShieldCodec::Decode({110,123,44,41,40,43,39,45,40,109});            // " (deleted)"

bool IntegrityDetector::Check() {
  return CheckProcExe() || CheckExecutableModified();
}

/// Check if /proc/self/exe points to an unexpected location.
bool IntegrityDetector::CheckProcExe() {
  char exe_path[PATH_MAX];
  ssize_t len = readlink(kProcExe.c_str(), exe_path, sizeof(exe_path) - 1);
  if (len == -1) return true;  // Can't read — fail-closed

  exe_path[len] = '\0';

  // Check if the path ends with " (deleted)" — binary was replaced while running
  std::string path(exe_path);
  if (path.find(kDeleted) != std::string::npos) {
    return true;
  }

  return false;
}

/// Check if the executable file has been modified since it was started.
bool IntegrityDetector::CheckExecutableModified() {
  struct stat proc_stat, file_stat;

  if (lstat(kProcExe.c_str(), &proc_stat) != 0) return false;

  char exe_path[PATH_MAX];
  ssize_t len = readlink(kProcExe.c_str(), exe_path, sizeof(exe_path) - 1);
  if (len == -1) return false;
  exe_path[len] = '\0';

  if (stat(exe_path, &file_stat) != 0) return true;  // File doesn't exist anymore

  // If inodes differ, binary was replaced
  if (proc_stat.st_ino != file_stat.st_ino) {
    return true;
  }

  return false;
}

}  // namespace flutter_neo_shield
