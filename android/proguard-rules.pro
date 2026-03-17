# ============================================================================
# ProGuard / R8 rules for flutter_neo_shield plugin
# ============================================================================
# These rules apply when the plugin AAR itself is built with minification.
# For consumer-app rules, see consumer-proguard-rules.pro.
# ============================================================================

# ── Optimization flags ──────────────────────────────────────────────────────
-optimizationpasses 5
-allowaccessmodification
-repackageclasses 'fns'
-overloadaggressively

# ── Keep Flutter plugin entry point ─────────────────────────────────────────
# The Flutter engine instantiates this class by reflection via the
# GeneratedPluginRegistrant. All FlutterPlugin / MethodCallHandler /
# ActivityAware interface methods must survive.
-keep class com.neelakandan.flutter_neo_shield.FlutterNeoShieldPlugin {
    public <init>();
    public void onAttachedToEngine(io.flutter.embedding.engine.plugins.FlutterPlugin$FlutterPluginBinding);
    public void onDetachedFromEngine(io.flutter.embedding.engine.plugins.FlutterPlugin$FlutterPluginBinding);
    public void onMethodCall(io.flutter.plugin.common.MethodCall, io.flutter.plugin.common.MethodChannel$Result);
    public void onAttachedToActivity(io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding);
    public void onDetachedFromActivity();
    public void onDetachedFromActivityForConfigChanges();
    public void onReattachedToActivityForConfigChanges(io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding);
}

# ── Keep ShieldCodec ────────────────────────────────────────────────────────
# ShieldCodec fields and decode() are referenced from the plugin at runtime
# for channel/method name resolution. The class is internal but must not be
# renamed or have its members stripped, since the encoded int-arrays and the
# decode function are used to build channel names at registration time.
-keep class com.neelakandan.flutter_neo_shield.ShieldCodec {
    *;
}

# ── Obfuscate ALL detector / screen classes ─────────────────────────────────
# These are internal implementation details. We explicitly allow R8 to rename,
# shrink, and optimise them. No -keep rules means full obfuscation.
# (Listed here only as documentation — the absence of -keep is what matters.)
#
#   com.neelakandan.flutter_neo_shield.rasp.RootDetector
#   com.neelakandan.flutter_neo_shield.rasp.EmulatorDetector
#   com.neelakandan.flutter_neo_shield.rasp.DebuggerDetector
#   com.neelakandan.flutter_neo_shield.rasp.HookDetector
#   com.neelakandan.flutter_neo_shield.rasp.FridaDetector
#   com.neelakandan.flutter_neo_shield.rasp.IntegrityDetector
#   com.neelakandan.flutter_neo_shield.rasp.DeveloperModeDetector
#   com.neelakandan.flutter_neo_shield.rasp.SignatureDetector
#   com.neelakandan.flutter_neo_shield.rasp.NativeDebugDetector
#   com.neelakandan.flutter_neo_shield.rasp.NetworkThreatDetector
#   com.neelakandan.flutter_neo_shield.screen.ScreenProtector
#   com.neelakandan.flutter_neo_shield.screen.ScreenRecordingDetector

# ── Keep Kotlin metadata only where needed ──────────────────────────────────
-dontwarn kotlin.**
-dontwarn kotlinx.**

# Keep Kotlin intrinsics so that null-checks and other compiler-generated
# helpers work correctly after obfuscation.
-keep class kotlin.Metadata { *; }
-keep class kotlin.jvm.internal.** { *; }

# ── Suppress warnings for Flutter engine classes ────────────────────────────
-dontwarn io.flutter.**

# ── Remove logging in release builds ────────────────────────────────────────
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
}
