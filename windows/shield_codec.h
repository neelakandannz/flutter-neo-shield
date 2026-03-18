#ifndef SHIELD_CODEC_H_
#define SHIELD_CODEC_H_

#include <cstdint>
#include <string>
#include <vector>

namespace flutter_neo_shield {

class ShieldCodec {
 public:
  static std::string Decode(const std::vector<uint8_t>& encoded) {
    // Key derived from arithmetic operations
    static const uint8_t key[] = {
        0x32 + 0x1C,  // 0x4E
        0x41 + 0x12,  // 0x53
        0x24 + 0x24,  // 0x48
        0x3E + 0x0E,  // 0x4C
        0x22 + 0x22   // 0x44
    };
    static const size_t key_len = sizeof(key) / sizeof(key[0]);

    std::string result;
    result.reserve(encoded.size());
    for (size_t i = 0; i < encoded.size(); ++i) {
      result.push_back(static_cast<char>(encoded[i] ^ key[i % key_len]));
    }
    return result;
  }

  // Channel names (encoded)
  static const std::vector<uint8_t>& ChannelRasp() {
    static const std::vector<uint8_t> v = {45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 60, 50, 59, 60};
    return v;
  }
  static const std::vector<uint8_t>& ChannelScreen() {
    static const std::vector<uint8_t> v = {45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 61, 48, 58, 41, 33, 32};
    return v;
  }
  static const std::vector<uint8_t>& ChannelMemory() {
    static const std::vector<uint8_t> v = {45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 35, 54, 37, 35, 54, 55};
    return v;
  }
  static const std::vector<uint8_t>& ChannelScreenEvents() {
    static const std::vector<uint8_t> v = {45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 61, 48, 58, 41, 33, 32, 12, 45, 58, 33, 32, 39, 59};
    return v;
  }

  // Method names (encoded)
  static const std::vector<uint8_t>& MethodCheckDebugger() {
    static const std::vector<uint8_t> v = {45, 59, 45, 47, 47, 10, 54, 42, 57, 35, 41, 54, 58};
    return v;
  }
  static const std::vector<uint8_t>& MethodCheckRoot() {
    static const std::vector<uint8_t> v = {45, 59, 45, 47, 47, 28, 60, 39, 56};
    return v;
  }
  static const std::vector<uint8_t>& MethodCheckEmulator() {
    static const std::vector<uint8_t> v = {45, 59, 45, 47, 47, 11, 62, 61, 32, 37, 58, 60, 58};
    return v;
  }
  static const std::vector<uint8_t>& MethodCheckFrida() {
    static const std::vector<uint8_t> v = {45, 59, 45, 47, 47, 8, 33, 33, 40, 37};
    return v;
  }
  static const std::vector<uint8_t>& MethodCheckHooks() {
    static const std::vector<uint8_t> v = {45, 59, 45, 47, 47, 6, 60, 39, 39, 55};
    return v;
  }
  static const std::vector<uint8_t>& MethodCheckIntegrity() {
    static const std::vector<uint8_t> v = {45, 59, 45, 47, 47, 7, 61, 60, 41, 35, 60, 58, 60, 53};
    return v;
  }
  static const std::vector<uint8_t>& MethodCheckDeveloperMode() {
    static const std::vector<uint8_t> v = {45, 59, 45, 47, 47, 10, 54, 62, 41, 40, 33, 35, 45, 62, 9, 33, 55, 45};
    return v;
  }
  static const std::vector<uint8_t>& MethodCheckSignature() {
    static const std::vector<uint8_t> v = {45, 59, 45, 47, 47, 29, 58, 47, 34, 37, 58, 38, 58, 41};
    return v;
  }
  static const std::vector<uint8_t>& MethodGetSignatureHash() {
    static const std::vector<uint8_t> v = {41, 54, 60, 31, 45, 41, 61, 41, 56, 49, 60, 54, 0, 45, 55, 38};
    return v;
  }
  static const std::vector<uint8_t>& MethodCheckNativeDebug() {
    static const std::vector<uint8_t> v = {45, 59, 45, 47, 47, 0, 50, 60, 37, 50, 43, 23, 45, 46, 49, 41};
    return v;
  }
  static const std::vector<uint8_t>& MethodCheckNetworkThreats() {
    static const std::vector<uint8_t> v = {45, 59, 45, 47, 47, 0, 54, 60, 59, 43, 60, 56, 28, 36, 54, 43, 50, 60, 63};
    return v;
  }
  static const std::vector<uint8_t>& MethodEnableScreenProtection() {
    static const std::vector<uint8_t> v = {43, 61, 41, 46, 40, 43, 0, 43, 62, 33, 43, 61, 24, 62, 43, 58, 54, 43, 56, 45, 33, 61};
    return v;
  }
  static const std::vector<uint8_t>& MethodDisableScreenProtection() {
    static const std::vector<uint8_t> v = {42, 58, 59, 45, 38, 34, 54, 27, 47, 54, 43, 54, 38, 28, 54, 33, 39, 45, 47, 48, 39, 60, 38};
    return v;
  }
  static const std::vector<uint8_t>& MethodIsScreenProtectionActive() {
    static const std::vector<uint8_t> v = {39, 32, 27, 47, 54, 43, 54, 38, 28, 54, 33, 39, 45, 47, 48, 39, 60, 38, 13, 39, 58, 58, 62, 41};
    return v;
  }
  static const std::vector<uint8_t>& MethodEnableAppSwitcherGuard() {
    static const std::vector<uint8_t> v = {43, 61, 41, 46, 40, 43, 18, 56, 60, 23, 57, 58, 60, 47, 44, 43, 33, 15, 57, 37, 60, 55};
    return v;
  }
  static const std::vector<uint8_t>& MethodDisableAppSwitcherGuard() {
    static const std::vector<uint8_t> v = {42, 58, 59, 45, 38, 34, 54, 9, 60, 52, 29, 36, 33, 56, 39, 38, 54, 58, 11, 49, 47, 33, 44};
    return v;
  }
  static const std::vector<uint8_t>& MethodIsScreenBeingRecorded() {
    static const std::vector<uint8_t> v = {39, 32, 27, 47, 54, 43, 54, 38, 14, 33, 39, 61, 47, 30, 33, 45, 60, 58, 40, 33, 42};
    return v;
  }
  static const std::vector<uint8_t>& MethodAllocateSecure() {
    static const std::vector<uint8_t> v = {47, 63, 36, 35, 39, 47, 39, 45, 31, 33, 45, 38, 58, 41};
    return v;
  }
  static const std::vector<uint8_t>& MethodReadSecure() {
    static const std::vector<uint8_t> v = {60, 54, 41, 40, 23, 43, 48, 61, 62, 33};
    return v;
  }
  static const std::vector<uint8_t>& MethodWipeSecure() {
    static const std::vector<uint8_t> v = {57, 58, 56, 41, 23, 43, 48, 61, 62, 33};
    return v;
  }
  static const std::vector<uint8_t>& MethodWipeAll() {
    static const std::vector<uint8_t> v = {57, 58, 56, 41, 5, 34, 63};
    return v;
  }

  // Location method names
  static const std::vector<uint8_t>& ChannelLocation() {
    static const std::vector<uint8_t> v = {45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 34, 60, 43, 45, 48, 39, 60, 38};
    return v;
  }
  static const std::vector<uint8_t>& ChannelLocationEvents() {
    static const std::vector<uint8_t> v = {45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 34, 60, 43, 45, 48, 39, 60, 38, 19, 33, 56, 54, 38, 56, 55};
    return v;
  }
  static const std::vector<uint8_t>& MethodCheckFakeLocation() {
    static const std::vector<uint8_t> v = {45, 59, 45, 47, 47, 8, 50, 35, 41, 8, 33, 48, 41, 56, 45, 33, 61};
    return v;
  }
  static const std::vector<uint8_t>& MethodCheckMockProvider() {
    static const std::vector<uint8_t> v = {45, 59, 45, 47, 47, 3, 60, 43, 39, 20, 60, 60, 62, 45, 32, 43, 33};
    return v;
  }
  static const std::vector<uint8_t>& MethodCheckSpoofingApps() {
    static const std::vector<uint8_t> v = {45, 59, 45, 47, 47, 29, 35, 39, 35, 34, 39, 61, 47, 13, 52, 62, 32};
    return v;
  }
  static const std::vector<uint8_t>& MethodCheckLocationHooks() {
    static const std::vector<uint8_t> v = {45, 59, 45, 47, 47, 2, 60, 43, 45, 48, 39, 60, 38, 4, 43, 33, 56, 59};
    return v;
  }
  static const std::vector<uint8_t>& MethodCheckGpsAnomaly() {
    static const std::vector<uint8_t> v = {45, 59, 45, 47, 47, 9, 35, 59, 13, 42, 33, 62, 41, 32, 61};
    return v;
  }
  static const std::vector<uint8_t>& MethodCheckSensorFusion() {
    static const std::vector<uint8_t> v = {45, 59, 45, 47, 47, 29, 54, 38, 63, 43, 60, 21, 61, 63, 45, 33, 61};
    return v;
  }
  static const std::vector<uint8_t>& MethodCheckTemporalAnomaly() {
    static const std::vector<uint8_t> v = {45, 59, 45, 47, 47, 26, 54, 37, 60, 43, 60, 50, 36, 13, 42, 33, 62, 41, 32, 61};
    return v;
  }
};

}  // namespace flutter_neo_shield

#endif  // SHIELD_CODEC_H_
