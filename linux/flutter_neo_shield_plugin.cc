#include "include/flutter_neo_shield/flutter_neo_shield_plugin.h"

#include <flutter_linux/flutter_linux.h>
#include <gtk/gtk.h>

#include <cstring>
#include <map>
#include <string>
#include <vector>
#include <mutex>

#include "rasp/debugger_detector.h"
#include "rasp/privilege_detector.h"
#include "rasp/vm_detector.h"
#include "rasp/frida_detector.h"
#include "rasp/hook_detector.h"
#include "rasp/integrity_detector.h"
#include "rasp/developer_mode_detector.h"
#include "rasp/signature_detector.h"
#include "rasp/native_debug_detector.h"
#include "rasp/network_threat_detector.h"
#include "screen/screen_protector.h"
#include "screen/screen_recording_detector.h"
#include "shield_codec.h"

#define FLUTTER_NEO_SHIELD_PLUGIN(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), flutter_neo_shield_plugin_get_type(), \
                              FlutterNeoShieldPlugin))

struct _FlutterNeoShieldPlugin {
  GObject parent_instance;
  std::map<std::string, std::vector<uint8_t>>* secure_storage;
  std::mutex* storage_mutex;
  flutter_neo_shield::ScreenProtector* screen_protector;
};

G_DEFINE_TYPE(FlutterNeoShieldPlugin, flutter_neo_shield_plugin, g_object_get_type())

static void handle_method_call(
    FlutterNeoShieldPlugin* self,
    FlMethodCall* method_call) {
  g_autoptr(FlMethodResponse) response = nullptr;
  const gchar* method = fl_method_call_get_name(method_call);
  FlValue* args = fl_method_call_get_args(method_call);
  const std::string method_str(method);

  using Codec = flutter_neo_shield::ShieldCodec;

  // Memory Shield
  if (method_str == Codec::Decode(Codec::MethodAllocateSecure())) {
    FlValue* id_val = fl_value_lookup_string(args, "id");
    FlValue* data_val = fl_value_lookup_string(args, "data");
    if (id_val && data_val && fl_value_get_type(id_val) == FL_VALUE_TYPE_STRING &&
        fl_value_get_type(data_val) == FL_VALUE_TYPE_UINT8_LIST) {
      std::string id(fl_value_get_string(id_val));
      const uint8_t* data = fl_value_get_uint8_list(data_val);
      size_t len = fl_value_get_length(data_val);
      std::lock_guard<std::mutex> lock(*self->storage_mutex);
      (*self->secure_storage)[id] = std::vector<uint8_t>(data, data + len);
      response = FL_METHOD_RESPONSE(fl_method_success_response_new(fl_value_new_null()));
    } else {
      response = FL_METHOD_RESPONSE(fl_method_error_response_new(
          "INVALID_ARGS", "id and data required", nullptr));
    }
  }
  else if (method_str == Codec::Decode(Codec::MethodReadSecure())) {
    FlValue* id_val = fl_value_lookup_string(args, "id");
    if (id_val && fl_value_get_type(id_val) == FL_VALUE_TYPE_STRING) {
      std::string id(fl_value_get_string(id_val));
      std::lock_guard<std::mutex> lock(*self->storage_mutex);
      auto it = self->secure_storage->find(id);
      if (it != self->secure_storage->end()) {
        g_autoptr(FlValue) result = fl_value_new_uint8_list(
            it->second.data(), it->second.size());
        response = FL_METHOD_RESPONSE(fl_method_success_response_new(result));
      } else {
        response = FL_METHOD_RESPONSE(fl_method_error_response_new(
            "NOT_FOUND", "No secure data found", nullptr));
      }
    } else {
      response = FL_METHOD_RESPONSE(fl_method_error_response_new(
          "NOT_FOUND", "No secure data found", nullptr));
    }
  }
  else if (method_str == Codec::Decode(Codec::MethodWipeSecure())) {
    FlValue* id_val = fl_value_lookup_string(args, "id");
    if (id_val && fl_value_get_type(id_val) == FL_VALUE_TYPE_STRING) {
      std::string id(fl_value_get_string(id_val));
      std::lock_guard<std::mutex> lock(*self->storage_mutex);
      auto it = self->secure_storage->find(id);
      if (it != self->secure_storage->end()) {
        if (!it->second.empty()) {
          explicit_bzero(it->second.data(), it->second.size());
        }
        self->secure_storage->erase(it);
      }
    }
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(fl_value_new_null()));
  }
  else if (method_str == Codec::Decode(Codec::MethodWipeAll())) {
    std::lock_guard<std::mutex> lock(*self->storage_mutex);
    for (auto& pair : *self->secure_storage) {
      if (!pair.second.empty()) {
        explicit_bzero(pair.second.data(), pair.second.size());
      }
    }
    self->secure_storage->clear();
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(fl_value_new_null()));
  }
  // RASP Shield
  else if (method_str == Codec::Decode(Codec::MethodCheckDebugger())) {
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(
        fl_value_new_bool(flutter_neo_shield::DebuggerDetector::Check())));
  }
  else if (method_str == Codec::Decode(Codec::MethodCheckRoot())) {
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(
        fl_value_new_bool(flutter_neo_shield::PrivilegeDetector::Check())));
  }
  else if (method_str == Codec::Decode(Codec::MethodCheckEmulator())) {
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(
        fl_value_new_bool(flutter_neo_shield::VMDetector::Check())));
  }
  else if (method_str == Codec::Decode(Codec::MethodCheckHooks())) {
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(
        fl_value_new_bool(flutter_neo_shield::HookDetector::Check())));
  }
  else if (method_str == Codec::Decode(Codec::MethodCheckFrida())) {
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(
        fl_value_new_bool(flutter_neo_shield::FridaDetector::Check())));
  }
  else if (method_str == Codec::Decode(Codec::MethodCheckIntegrity())) {
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(
        fl_value_new_bool(flutter_neo_shield::IntegrityDetector::Check())));
  }
  else if (method_str == Codec::Decode(Codec::MethodCheckDeveloperMode())) {
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(
        fl_value_new_bool(flutter_neo_shield::DeveloperModeDetector::Check())));
  }
  else if (method_str == Codec::Decode(Codec::MethodCheckSignature())) {
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(
        fl_value_new_bool(flutter_neo_shield::SignatureDetector::Check())));
  }
  else if (method_str == Codec::Decode(Codec::MethodGetSignatureHash())) {
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(fl_value_new_null()));
  }
  else if (method_str == Codec::Decode(Codec::MethodCheckNativeDebug())) {
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(
        fl_value_new_bool(flutter_neo_shield::NativeDebugDetector::Check())));
  }
  else if (method_str == Codec::Decode(Codec::MethodCheckNetworkThreats())) {
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(
        fl_value_new_bool(flutter_neo_shield::NetworkThreatDetector::CheckSimple())));
  }
  // Screen Shield
  else if (method_str == Codec::Decode(Codec::MethodEnableScreenProtection())) {
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(
        fl_value_new_bool(self->screen_protector->Enable())));
  }
  else if (method_str == Codec::Decode(Codec::MethodDisableScreenProtection())) {
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(
        fl_value_new_bool(self->screen_protector->Disable())));
  }
  else if (method_str == Codec::Decode(Codec::MethodIsScreenProtectionActive())) {
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(
        fl_value_new_bool(self->screen_protector->IsActive())));
  }
  else if (method_str == Codec::Decode(Codec::MethodEnableAppSwitcherGuard())) {
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(fl_value_new_bool(false)));
  }
  else if (method_str == Codec::Decode(Codec::MethodDisableAppSwitcherGuard())) {
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(fl_value_new_bool(false)));
  }
  else if (method_str == Codec::Decode(Codec::MethodIsScreenBeingRecorded())) {
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(
        fl_value_new_bool(flutter_neo_shield::ScreenRecordingDetector::IsRecording())));
  }
  else {
    response = FL_METHOD_RESPONSE(fl_method_not_implemented_response_new());
  }

  fl_method_call_respond(method_call, response, nullptr);
}

static void method_call_cb(FlMethodChannel* channel, FlMethodCall* method_call,
                           gpointer user_data) {
  FlutterNeoShieldPlugin* plugin = FLUTTER_NEO_SHIELD_PLUGIN(user_data);
  handle_method_call(plugin, method_call);
}

static void flutter_neo_shield_plugin_dispose(GObject* object) {
  FlutterNeoShieldPlugin* self = FLUTTER_NEO_SHIELD_PLUGIN(object);

  // Secure wipe all stored data
  if (self->secure_storage) {
    for (auto& pair : *self->secure_storage) {
      if (!pair.second.empty()) {
        explicit_bzero(pair.second.data(), pair.second.size());
      }
    }
    delete self->secure_storage;
    self->secure_storage = nullptr;
  }

  delete self->storage_mutex;
  self->storage_mutex = nullptr;
  delete self->screen_protector;
  self->screen_protector = nullptr;

  G_OBJECT_CLASS(flutter_neo_shield_plugin_parent_class)->dispose(object);
}

static void flutter_neo_shield_plugin_class_init(FlutterNeoShieldPluginClass* klass) {
  G_OBJECT_CLASS(klass)->dispose = flutter_neo_shield_plugin_dispose;
}

static void flutter_neo_shield_plugin_init(FlutterNeoShieldPlugin* self) {
  self->secure_storage = new std::map<std::string, std::vector<uint8_t>>();
  self->storage_mutex = new std::mutex();
  self->screen_protector = new flutter_neo_shield::ScreenProtector();
}

void flutter_neo_shield_plugin_register_with_registrar(FlPluginRegistrar* registrar) {
  FlutterNeoShieldPlugin* plugin = FLUTTER_NEO_SHIELD_PLUGIN(
      g_object_new(flutter_neo_shield_plugin_get_type(), nullptr));

  using Codec = flutter_neo_shield::ShieldCodec;

  g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();

  g_autoptr(FlMethodChannel) memory_channel =
      fl_method_channel_new(fl_plugin_registrar_get_messenger(registrar),
                            Codec::Decode(Codec::ChannelMemory()).c_str(),
                            FL_METHOD_CODEC(codec));
  fl_method_channel_set_method_call_handler(memory_channel, method_call_cb,
                                             g_object_ref(plugin), g_object_unref);

  g_autoptr(FlMethodChannel) rasp_channel =
      fl_method_channel_new(fl_plugin_registrar_get_messenger(registrar),
                            Codec::Decode(Codec::ChannelRasp()).c_str(),
                            FL_METHOD_CODEC(codec));
  fl_method_channel_set_method_call_handler(rasp_channel, method_call_cb,
                                             g_object_ref(plugin), g_object_unref);

  g_autoptr(FlMethodChannel) screen_channel =
      fl_method_channel_new(fl_plugin_registrar_get_messenger(registrar),
                            Codec::Decode(Codec::ChannelScreen()).c_str(),
                            FL_METHOD_CODEC(codec));
  fl_method_channel_set_method_call_handler(screen_channel, method_call_cb,
                                             g_object_ref(plugin), g_object_unref);

  g_object_unref(plugin);
}
