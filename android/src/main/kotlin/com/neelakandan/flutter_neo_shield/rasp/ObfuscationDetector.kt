package com.neelakandan.flutter_neo_shield.rasp
class ObfuscationDetector {
    fun check(): Boolean {
        return try { this::class.java.name.contains("ObfuscationDetector") } catch (e: Exception) { false }
    }
}
