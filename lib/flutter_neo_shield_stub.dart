/// Desktop platform stubs for flutter_neo_shield.
///
/// All features (Log Shield, Clipboard Shield, Memory Shield, String Shield)
/// work in pure Dart. These classes only satisfy Flutter's plugin registration.
/// On desktop platforms, Memory Shield uses the Dart-side byte wipe instead of
/// native platform channels.
library;

/// macOS plugin stub.
class FlutterNeoShieldMacOS {
  /// Registers the macOS plugin (no-op — all features are pure Dart).
  static void registerWith() {}
}

/// Windows plugin stub.
class FlutterNeoShieldWindows {
  /// Registers the Windows plugin (no-op — all features are pure Dart).
  static void registerWith() {}
}

/// Linux plugin stub.
class FlutterNeoShieldLinux {
  /// Registers the Linux plugin (no-op — all features are pure Dart).
  static void registerWith() {}
}
