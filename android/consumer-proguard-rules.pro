# ============================================================================
# Consumer ProGuard / R8 rules for flutter_neo_shield
# ============================================================================
# These rules are automatically applied to any app that depends on this plugin.
# Keep ONLY what is strictly necessary for the plugin to function; everything
# else (detectors, internal helpers) will be obfuscated by the host app's R8.
# ============================================================================

# ── Plugin entry point (instantiated by GeneratedPluginRegistrant) ──────────
-keep class com.neelakandan.flutter_neo_shield.FlutterNeoShieldPlugin {
    public <init>();
}

# ── ShieldCodec (used internally for channel registration) ──────────────────
# The codec's fields and decode method must survive so that channel names
# resolve correctly at runtime.
-keep class com.neelakandan.flutter_neo_shield.ShieldCodec {
    *;
}

# ── Kotlin intrinsics required at runtime ───────────────────────────────────
-keep class kotlin.jvm.internal.Intrinsics { *; }

# ── Suppress warnings ──────────────────────────────────────────────────────
-dontwarn io.flutter.**
-dontwarn kotlin.**
-dontwarn kotlinx.**
