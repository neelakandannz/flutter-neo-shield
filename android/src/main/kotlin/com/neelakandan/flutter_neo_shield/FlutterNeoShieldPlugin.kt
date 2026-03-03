package com.neelakandan.flutter_neo_shield

import androidx.annotation.NonNull
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result

/**
 * FlutterNeoShieldPlugin — Android platform implementation.
 *
 * Provides native memory allocation and secure wipe operations
 * for the Memory Shield module.
 */
class FlutterNeoShieldPlugin : FlutterPlugin, MethodCallHandler {
    private lateinit var channel: MethodChannel
    private val secureStorage = HashMap<String, ByteArray>()

    override fun onAttachedToEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(binding.binaryMessenger, "com.neelakandan.flutter_neo_shield/memory")
        channel.setMethodCallHandler(this)
    }

    override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
        when (call.method) {
            "allocateSecure" -> {
                val id = call.argument<String>("id")
                val data = call.argument<ByteArray>("data")
                if (id != null && data != null) {
                    secureStorage[id] = data.copyOf()
                    result.success(null)
                } else {
                    result.error("INVALID_ARGS", "id and data are required", null)
                }
            }
            "readSecure" -> {
                val id = call.argument<String>("id")
                if (id != null && secureStorage.containsKey(id)) {
                    result.success(secureStorage[id])
                } else {
                    result.error("NOT_FOUND", "No secure data with id: $id", null)
                }
            }
            "wipeSecure" -> {
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
            "wipeAll" -> {
                for (entry in secureStorage.values) {
                    entry.fill(0)
                }
                secureStorage.clear()
                result.success(null)
            }
            else -> {
                result.notImplemented()
            }
        }
    }

    override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
        // Wipe all on detach for safety.
        for (entry in secureStorage.values) {
            entry.fill(0)
        }
        secureStorage.clear()
        channel.setMethodCallHandler(null)
    }
}
