#ifndef LOCATION_SHIELD_HANDLER_H_
#define LOCATION_SHIELD_HANDLER_H_

#include <flutter/method_call.h>
#include <flutter/method_result.h>
#include <flutter/encodable_value.h>

#include <string>
#include <map>
#include <vector>
#include <memory>

namespace flutter_neo_shield {

class LocationShieldHandler {
 public:
  LocationShieldHandler();
  ~LocationShieldHandler();

  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue>& method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);

 private:
  void HandleFullCheck(
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);

  // Layer 1: Mock provider detection
  bool CheckMockProvider();
  // Layer 2: Spoofing app detection
  std::vector<std::string> CheckSpoofingApps();
  // Layer 3: Location hook detection
  bool CheckLocationHooks();
  // Layer 4: GPS signal anomaly (limited on Windows)
  double CheckGpsAnomaly();
  // Layer 5: Sensor fusion (limited on Windows)
  double CheckSensorFusion();
  // Layer 6: Temporal anomaly
  double CheckTemporalAnomaly();
  // Layer 7: Integrity aggregation
  double ComputeConfidence(const std::map<std::string, double>& scores);

  // Temporal anomaly state
  struct LocationSnapshot {
    double latitude;
    double longitude;
    double altitude;
    double speed;
    double bearing;
    double accuracy;
    int64_t timestamp;
    int64_t system_timestamp;
  };
  std::vector<LocationSnapshot> location_history_;
  double last_temporal_score_ = 0.0;

  double HaversineDistance(double lat1, double lon1, double lat2, double lon2);
};

}  // namespace flutter_neo_shield

#endif  // LOCATION_SHIELD_HANDLER_H_
