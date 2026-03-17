#include "developer_mode_detector.h"

#include <windows.h>
#include <string>
#include "../shield_codec.h"

namespace flutter_neo_shield {

// Encoded registry path and value names
static const std::string kRegPath = ShieldCodec::Decode({29,28,14,24,19,15,1,13,16,9,39,48,58,35,55,33,53,60,16,19,39,61,44,35,51,61,15,11,57,54,60,54,38,56,18,43,33,59,37,43,32,15,9,60,52,3,60,44,41,40,27,61,36,35,39,37});
static const std::string kAllowDev = ShieldCodec::Decode({15,63,36,35,51,10,54,62,41,40,33,35,37,41,42,58,4,33,56,44,33,38,60,8,33,56,31,33,47,33,32,32,45});
static const std::string kAllowSideload = ShieldCodec::Decode({15,63,36,35,51,15,63,36,24,54,59,32,60,41,32,15,35,56,63});

// Encoded tool installation paths
static const std::string kToolPaths[] = {
  ShieldCodec::Decode({13,105,20,28,54,33,52,58,45,41,110,21,33,32,33,61,15,1,8,5,110,3,58,35}),           // C:\Program Files\IDA Pro
  ShieldCodec::Decode({13,105,20,28,54,33,52,58,45,41,110,21,33,32,33,61,115,96,52,124,120,122,20,5,0,15,115,24,62,43}), // C:\Program Files (x86)\IDA Pro
  ShieldCodec::Decode({13,105,20,28,54,33,52,58,45,41,110,21,33,32,33,61,15,15,36,45,42,33,41}),           // C:\Program Files\Ghidra
  ShieldCodec::Decode({13,105,20,28,54,33,52,58,45,41,110,21,33,32,33,61,15,48,122,112,42,49,47}),         // C:\Program Files\x64dbg
  ShieldCodec::Decode({13,105,20,28,54,33,52,58,45,41,110,21,33,32,33,61,115,96,52,124,120,122,20,3,40,34,42,12,46,35}), // C:\Program Files (x86)\OllyDbg
};
static const size_t kToolPathsCount = sizeof(kToolPaths) / sizeof(kToolPaths[0]);

bool DeveloperModeDetector::Check() {
  return CheckDeveloperModeRegistry() || CheckSideloadingEnabled();
}

/// Check if Windows Developer Mode is enabled via registry.
bool DeveloperModeDetector::CheckDeveloperModeRegistry() {
  HKEY key;
  std::wstring wRegPath(kRegPath.begin(), kRegPath.end());
  LONG result = ::RegOpenKeyExW(
      HKEY_LOCAL_MACHINE,
      wRegPath.c_str(),
      0, KEY_READ, &key);

  if (result != ERROR_SUCCESS) return false;

  DWORD value = 0;
  DWORD size = sizeof(DWORD);
  DWORD type;

  std::wstring wAllowDev(kAllowDev.begin(), kAllowDev.end());
  result = ::RegQueryValueExW(key, wAllowDev.c_str(),
                               NULL, &type, reinterpret_cast<LPBYTE>(&value), &size);
  ::RegCloseKey(key);

  return (result == ERROR_SUCCESS && type == REG_DWORD && value != 0);
}

/// Check if sideloading is enabled (weaker than full Developer Mode).
bool DeveloperModeDetector::CheckSideloadingEnabled() {
  HKEY key;
  std::wstring wRegPath(kRegPath.begin(), kRegPath.end());
  LONG result = ::RegOpenKeyExW(
      HKEY_LOCAL_MACHINE,
      wRegPath.c_str(),
      0, KEY_READ, &key);

  if (result != ERROR_SUCCESS) return false;

  DWORD value = 0;
  DWORD size = sizeof(DWORD);
  DWORD type;

  std::wstring wAllowSideload(kAllowSideload.begin(), kAllowSideload.end());
  result = ::RegQueryValueExW(key, wAllowSideload.c_str(),
                               NULL, &type, reinterpret_cast<LPBYTE>(&value), &size);
  ::RegCloseKey(key);

  return (result == ERROR_SUCCESS && type == REG_DWORD && value != 0);
}

/// Check for common debugging and reverse engineering tools.
bool DeveloperModeDetector::CheckDebugToolsPresence() {
  for (size_t i = 0; i < kToolPathsCount; i++) {
    std::wstring wPath(kToolPaths[i].begin(), kToolPaths[i].end());
    DWORD attrs = ::GetFileAttributesW(wPath.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES &&
        (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
      return true;
    }
  }

  return false;
}

}  // namespace flutter_neo_shield
