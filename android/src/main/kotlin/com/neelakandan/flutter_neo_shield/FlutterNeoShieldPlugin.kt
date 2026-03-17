package com.neelakandan.flutter_neo_shield

import android.app.Activity
import androidx.annotation.NonNull
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result

/**
 * FlutterNeoShieldPlugin — Android platform implementation.
 *
 * Provides native memory allocation, secure wipe operations,
 * RASP checks, and screen protection.
 *
 * P3 Security Hardening: All RASP boolean results are wrapped through
 * [validateResult] which cross-checks with [SelfIntegrityChecker] and
 * performs cross-detector validation. If the plugin itself is hooked,
 * all security checks return true (detected).
 */
class FlutterNeoShieldPlugin : FlutterPlugin, MethodCallHandler, ActivityAware {
    private lateinit var channel: MethodChannel
    private lateinit var raspChannel: MethodChannel
    private lateinit var screenChannel: MethodChannel
    private var screenEventChannel: EventChannel? = null
    private val secureStorage = HashMap<String, ByteArray>()
    private val debuggerDetector = com.neelakandan.flutter_neo_shield.rasp.DebuggerDetector()
    private var applicationContext: android.content.Context? = null
    private var activity: Activity? = null
    private val screenProtector = com.neelakandan.flutter_neo_shield.screen.ScreenProtector()
    private val recordingDetector = com.neelakandan.flutter_neo_shield.screen.ScreenRecordingDetector()
    private var appSwitcherGuardEnabled = false

    override fun onAttachedToEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
        applicationContext = binding.applicationContext

        channel = MethodChannel(binding.binaryMessenger, ShieldCodec.decode(ShieldCodec.CH_MEMORY))
        channel.setMethodCallHandler(this)

        raspChannel = MethodChannel(binding.binaryMessenger, ShieldCodec.decode(ShieldCodec.CH_RASP))
        raspChannel.setMethodCallHandler(this)

        screenChannel = MethodChannel(binding.binaryMessenger, ShieldCodec.decode(ShieldCodec.CH_SCREEN))
        screenChannel.setMethodCallHandler(this)

        screenEventChannel = EventChannel(binding.binaryMessenger, ShieldCodec.decode(ShieldCodec.CH_SCREEN_EVENTS))
        screenEventChannel?.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                // Android does not have native screenshot/recording callbacks
                // below API 34. Events are sent on-demand or via polling.
            }

            override fun onCancel(arguments: Any?) {}
        })
    }

    override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
        when (call.method) {
            // Memory Shield
            ShieldCodec.decode(ShieldCodec.M_ALLOCATE_SECURE) -> {
                val id = call.argument<String>("id")
                val data = call.argument<ByteArray>("data")
                if (id != null && data != null) {
                    secureStorage[id] = data.copyOf()
                    result.success(null)
                } else {
                    result.error("INVALID_ARGS", "id and data are required", null)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_READ_SECURE) -> {
                val id = call.argument<String>("id")
                if (id != null && secureStorage.containsKey(id)) {
                    result.success(secureStorage[id])
                } else {
                    result.error("NOT_FOUND", "No secure data with id: $id", null)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_WIPE_SECURE) -> {
                val id = call.argument<String>("id")
                if (id != null && secureStorage.containsKey(id)) {
                    val data = secureStorage[id]!!
                    data.fill(0)
                    secureStorage.remove(id)
                    result.success(null)
                } else {
                    result.success(null)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_WIPE_ALL) -> {
                for (entry in secureStorage.values) {
                    entry.fill(0)
                }
                secureStorage.clear()
                result.success(null)
            }

            // RASP Shield — all boolean results are wrapped through validateResult()
            // for self-integrity and cross-detector validation.
            ShieldCodec.decode(ShieldCodec.M_CHECK_DEBUGGER) -> {
                result.success(validateResult(debuggerDetector.check()))
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_ROOT) -> {
                result.success(validateRootResult(com.neelakandan.flutter_neo_shield.rasp.RootDetector().check()))
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_EMULATOR) -> {
                result.success(validateResult(com.neelakandan.flutter_neo_shield.rasp.EmulatorDetector().check()))
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_HOOKS) -> {
                val context = applicationContext
                if (context != null) {
                    result.success(validateResult(com.neelakandan.flutter_neo_shield.rasp.HookDetector().check(context)))
                } else {
                    // Fail closed: report as detected when context unavailable.
                    result.success(true)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_FRIDA) -> {
                result.success(validateResult(com.neelakandan.flutter_neo_shield.rasp.FridaDetector().check()))
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_INTEGRITY) -> {
                val context = applicationContext
                if (context != null) {
                    result.success(validateResult(com.neelakandan.flutter_neo_shield.rasp.IntegrityDetector().check(context)))
                } else {
                    // Fail closed: report as detected when context unavailable.
                    result.success(true)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_DEVELOPER_MODE) -> {
                val context = applicationContext
                if (context != null) {
                    result.success(validateResult(com.neelakandan.flutter_neo_shield.rasp.DeveloperModeDetector().check(context)))
                } else {
                    // Fail closed: report as detected when context unavailable.
                    result.success(true)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_SIGNATURE) -> {
                val context = applicationContext
                if (context != null) {
                    result.success(validateResult(com.neelakandan.flutter_neo_shield.rasp.SignatureDetector().checkSimple(context)))
                } else {
                    result.success(true)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_GET_SIGNATURE_HASH) -> {
                val context = applicationContext
                if (context != null) {
                    result.success(com.neelakandan.flutter_neo_shield.rasp.SignatureDetector().getCurrentSignatureHash(context))
                } else {
                    result.success(null)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_NATIVE_DEBUG) -> {
                result.success(validateResult(com.neelakandan.flutter_neo_shield.rasp.NativeDebugDetector().check()))
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_NETWORK_THREATS) -> {
                val context = applicationContext
                if (context != null) {
                    result.success(validateResult(com.neelakandan.flutter_neo_shield.rasp.NetworkThreatDetector().checkSimple(context)))
                } else {
                    result.success(true)
                }
            }

            // Screen Shield
            ShieldCodec.decode(ShieldCodec.M_ENABLE_SCREEN_PROTECTION) -> {
                screenProtector.enable(activity, result)
            }
            ShieldCodec.decode(ShieldCodec.M_DISABLE_SCREEN_PROTECTION) -> {
                screenProtector.disable(activity, result)
            }
            ShieldCodec.decode(ShieldCodec.M_IS_SCREEN_PROTECTION_ACTIVE) -> {
                result.success(screenProtector.isActive(activity))
            }
            ShieldCodec.decode(ShieldCodec.M_ENABLE_APP_SWITCHER_GUARD) -> {
                // On Android, FLAG_SECURE already blanks the app switcher thumbnail.
                // Enabling screen protection implicitly guards the app switcher.
                // We wrap the result to also track the guard state.
                screenProtector.enable(activity, object : Result {
                    override fun success(value: Any?) {
                        val success = value as? Boolean ?: false
                        appSwitcherGuardEnabled = success
                        result.success(success)
                    }
                    override fun error(code: String, msg: String?, details: Any?) {
                        result.error(code, msg, details)
                    }
                    override fun notImplemented() {
                        result.notImplemented()
                    }
                })
            }
            ShieldCodec.decode(ShieldCodec.M_DISABLE_APP_SWITCHER_GUARD) -> {
                // Only disable FLAG_SECURE if screen protection itself isn't active
                appSwitcherGuardEnabled = false
                // Don't clear FLAG_SECURE here — it may be set for screen protection.
                // The app switcher guard is a logical flag on Android.
                result.success(true)
            }
            ShieldCodec.decode(ShieldCodec.M_IS_SCREEN_BEING_RECORDED) -> {
                result.success(recordingDetector.isRecordingOrMirroring(activity))
            }

            else -> {
                result.notImplemented()
            }
        }
    }

    // ActivityAware implementation
    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity
    }

    override fun onDetachedFromActivityForConfigChanges() {
        activity = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activity = binding.activity
    }

    override fun onDetachedFromActivity() {
        activity = null
    }

    /**
     * Cross-validates a RASP detection result with the self-integrity checker.
     *
     * If the detector returned false (not detected) but our own code has been
     * hooked, we override to true (detected) — because the "false" result
     * cannot be trusted if the detection code itself is compromised.
     */
    private fun validateResult(detected: Boolean): Boolean {
        if (detected) return true
        // If the detector says "clean" but we're hooked, override to detected
        if (com.neelakandan.flutter_neo_shield.rasp.SelfIntegrityChecker.isHooked()) {
            return true
        }
        return false
    }

    /**
     * Cross-detector validation: if checkRoot returns false but hooks are
     * detected, flag root as suspicious (hook frameworks hide root).
     */
    private fun validateRootResult(rootDetected: Boolean): Boolean {
        if (rootDetected) return true
        // Cross-check: hook frameworks often hide root status
        val context = applicationContext
        if (context != null) {
            val hooksDetected = com.neelakandan.flutter_neo_shield.rasp.HookDetector().check(context)
            if (hooksDetected) return true
        }
        return validateResult(rootDetected)
    }

    override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
        // Wipe all on detach for safety.
        for (entry in secureStorage.values) {
            entry.fill(0)
        }
        secureStorage.clear()
        channel.setMethodCallHandler(null)
        raspChannel.setMethodCallHandler(null)
        screenChannel.setMethodCallHandler(null)
        screenEventChannel?.setStreamHandler(null)
    }
}
