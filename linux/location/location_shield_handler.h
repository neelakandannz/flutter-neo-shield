#ifndef LOCATION_SHIELD_HANDLER_H_
#define LOCATION_SHIELD_HANDLER_H_

#include <flutter_linux/flutter_linux.h>
#include <string>
#include <map>
#include <vector>

namespace flutter_neo_shield {

class LocationShieldHandler {
 public:
  LocationShieldHandler();
  ~LocationShieldHandler();

  FlMethodResponse* HandleMethodCall(const gchar* method, FlValue* args);

 private:
  FlMethodResponse* HandleFullCheck();

  bool CheckMockProvider();
  std::vector<std::string> CheckSpoofingApps();
  bool CheckLocationHooks();
  double CheckGpsAnomaly();
  double CheckSensorFusion();
  double CheckTemporalAnomaly();
  double ComputeConfidence(const std::map<std::string, double>& scores);

  double last_temporal_score_ = 0.0;
};

}  // namespace flutter_neo_shield

#endif  // LOCATION_SHIELD_HANDLER_H_
