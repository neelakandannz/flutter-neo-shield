#include "location_shield_handler.h"

#include <cmath>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <dlfcn.h>
#include <unistd.h>

#include "../shield_codec.h"

namespace flutter_neo_shield {

LocationShieldHandler::LocationShieldHandler() {}
LocationShieldHandler::~LocationShieldHandler() {}

FlMethodResponse* LocationShieldHandler::HandleMethodCall(
    const gchar* method, FlValue* args) {
  const std::string method_str(method);
  using Codec = ShieldCodec;

  if (method_str == Codec::Decode(Codec::MethodCheckFakeLocation())) {
    return HandleFullCheck();
  }
  else if (method_str == Codec::Decode(Codec::MethodCheckMockProvider())) {
    return FL_METHOD_RESPONSE(fl_method_success_response_new(
        fl_value_new_bool(CheckMockProvider())));
  }
  else if (method_str == Codec::Decode(Codec::MethodCheckSpoofingApps())) {
    auto apps = CheckSpoofingApps();
    g_autoptr(FlValue) map = fl_value_new_map();
    fl_value_set_string_take(map, "detected", fl_value_new_bool(!apps.empty()));
    g_autoptr(FlValue) app_list = fl_value_new_list();
    for (const auto& app : apps) {
      fl_value_append_take(app_list, fl_value_new_string(app.c_str()));
    }
    fl_value_set_string(map, "detectedApps", app_list);
    return FL_METHOD_RESPONSE(fl_method_success_response_new(map));
  }
  else if (method_str == Codec::Decode(Codec::MethodCheckLocationHooks())) {
    return FL_METHOD_RESPONSE(fl_method_success_response_new(
        fl_value_new_bool(CheckLocationHooks())));
  }
  else if (method_str == Codec::Decode(Codec::MethodCheckGpsAnomaly())) {
    return FL_METHOD_RESPONSE(fl_method_success_response_new(
        fl_value_new_float(CheckGpsAnomaly())));
  }
  else if (method_str == Codec::Decode(Codec::MethodCheckSensorFusion())) {
    return FL_METHOD_RESPONSE(fl_method_success_response_new(
        fl_value_new_float(CheckSensorFusion())));
  }
  else if (method_str == Codec::Decode(Codec::MethodCheckTemporalAnomaly())) {
    return FL_METHOD_RESPONSE(fl_method_success_response_new(
        fl_value_new_float(CheckTemporalAnomaly())));
  }

  return nullptr;  // Not handled
}

FlMethodResponse* LocationShieldHandler::HandleFullCheck() {
  std::map<std::string, double> scores;
  std::vector<std::string> detected_methods;

  // Layer 1
  bool mock = CheckMockProvider();
  scores["mockProvider"] = mock ? 1.0 : 0.0;
  if (mock) detected_methods.push_back("mockProvider");

  // Layer 2
  auto apps = CheckSpoofingApps();
  double spoof_score = apps.empty() ? 0.0 : 0.8;
  scores["spoofingApp"] = spoof_score;
  if (spoof_score > 0.3) detected_methods.push_back("spoofingApp");

  // Layer 3
  bool hooks = CheckLocationHooks();
  scores["locationHook"] = hooks ? 0.95 : 0.0;
  if (hooks) detected_methods.push_back("locationHook");

  // Layer 4
  scores["gpsSignal"] = CheckGpsAnomaly();
  if (scores["gpsSignal"] > 0.3) detected_methods.push_back("gpsSignal");

  // Layer 5
  scores["sensorFusion"] = CheckSensorFusion();

  // Layer 6
  scores["temporalAnomaly"] = CheckTemporalAnomaly();
  if (scores["temporalAnomaly"] > 0.3) detected_methods.push_back("temporalAnomaly");

  // Layer 7
  double confidence = ComputeConfidence(scores);
  scores["integrity"] = confidence;
  bool is_spoofed = confidence >= 0.5;

  g_autoptr(FlValue) result = fl_value_new_map();
  fl_value_set_string_take(result, "isSpoofed", fl_value_new_bool(is_spoofed));
  fl_value_set_string_take(result, "confidence", fl_value_new_float(confidence));

  g_autoptr(FlValue) methods_list = fl_value_new_list();
  for (const auto& m : detected_methods) {
    fl_value_append_take(methods_list, fl_value_new_string(m.c_str()));
  }
  fl_value_set_string(result, "detectedMethods", methods_list);

  g_autoptr(FlValue) layer_scores = fl_value_new_map();
  for (const auto& s : scores) {
    fl_value_set_string_take(layer_scores, s.first.c_str(), fl_value_new_float(s.second));
  }
  fl_value_set_string(result, "layerScores", layer_scores);

  fl_value_set_string_take(result, "summary",
      fl_value_new_string(is_spoofed ? "Fake location detected" : "Location appears authentic"));

  return FL_METHOD_RESPONSE(fl_method_success_response_new(result));
}

// Layer 1: Check gpsd for virtual/mock GPS devices
bool LocationShieldHandler::CheckMockProvider() {
  // Check if gpsd is running with a virtual device
  std::ifstream maps("/proc/self/maps");
  if (!maps.is_open()) return false;

  std::string line;
  while (std::getline(maps, line)) {
    // Check for fake GPS libraries loaded via LD_PRELOAD
    if (line.find("fakegps") != std::string::npos ||
        line.find("mockloc") != std::string::npos ||
        line.find("gpsspoof") != std::string::npos) {
      return true;
    }
  }

  // Check LD_PRELOAD
  const char* preload = getenv("LD_PRELOAD");
  if (preload) {
    std::string preload_str(preload);
    if (preload_str.find("fakegps") != std::string::npos ||
        preload_str.find("mocklocation") != std::string::npos ||
        preload_str.find("libfakeloc") != std::string::npos) {
      return true;
    }
  }

  return false;
}

// Layer 2: Check for GPS simulation processes
std::vector<std::string> LocationShieldHandler::CheckSpoofingApps() {
  std::vector<std::string> detected;

  const char* suspicious[] = {
      "gpsfake", "fakegps", "gps-simulator", "gpssim",
      "mock-gps", "nmea-simulator", "gpsd-fake",
  };

  // Read /proc to find running processes
  FILE* fp = popen("ps -eo comm 2>/dev/null", "r");
  if (!fp) return detected;

  char buffer[256];
  while (fgets(buffer, sizeof(buffer), fp)) {
    std::string proc(buffer);
    // Remove newline
    if (!proc.empty() && proc.back() == '\n') proc.pop_back();

    for (const auto& s : suspicious) {
      if (proc.find(s) != std::string::npos) {
        detected.push_back(proc);
      }
    }
  }
  pclose(fp);

  return detected;
}

// Layer 3: Check for hooks on location-related functions
bool LocationShieldHandler::CheckLocationHooks() {
  // Check LD_PRELOAD for location-related interposition
  const char* preload = getenv("LD_PRELOAD");
  if (preload) {
    std::string p(preload);
    if (p.find("location") != std::string::npos ||
        p.find("gps") != std::string::npos ||
        p.find("geoclue") != std::string::npos) {
      return true;
    }
  }

  // Check /proc/self/maps for suspicious libraries
  std::ifstream maps("/proc/self/maps");
  if (maps.is_open()) {
    std::string line;
    while (std::getline(maps, line)) {
      if (line.find("frida") != std::string::npos ||
          line.find("libgadget") != std::string::npos) {
        return true;
      }
    }
  }

  return false;
}

// Layer 4: GPS signal anomaly (limited on Linux desktop)
double LocationShieldHandler::CheckGpsAnomaly() {
  return 0.0;
}

// Layer 5: Sensor fusion (not available on Linux desktop)
double LocationShieldHandler::CheckSensorFusion() {
  return 0.0;
}

// Layer 6: Temporal anomaly
double LocationShieldHandler::CheckTemporalAnomaly() {
  return last_temporal_score_;
}

// Layer 7: Weighted confidence
double LocationShieldHandler::ComputeConfidence(
    const std::map<std::string, double>& scores) {
  struct W { const char* key; double weight; };
  static const W weights[] = {
      {"mockProvider", 1.0}, {"spoofingApp", 0.9}, {"locationHook", 0.95},
      {"gpsSignal", 0.7}, {"sensorFusion", 0.8}, {"temporalAnomaly", 0.85},
  };

  double total_score = 0.0, total_weight = 0.0;
  for (const auto& w : weights) {
    auto it = scores.find(w.key);
    double score = (it != scores.end()) ? it->second : 0.0;
    total_score += score * w.weight;
    total_weight += w.weight;
  }

  if (total_weight <= 0.0) return 0.0;
  double normalized = total_score / total_weight;

  int triggered = 0;
  for (const auto& s : scores) {
    if (s.second > 0.3) triggered++;
  }

  double amplifier = triggered >= 4 ? 1.5 : triggered >= 3 ? 1.3 : triggered >= 2 ? 1.1 : 1.0;
  return std::min(normalized * amplifier, 1.0);
}

}  // namespace flutter_neo_shield
