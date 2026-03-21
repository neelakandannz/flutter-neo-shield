package com.neelakandan.flutter_neo_shield.rasp
import android.content.Context
import java.io.File
class CodeInjectionDetector {
    fun check(context: Context): Boolean {
        return try { checkUnexpectedDex(context) || checkSuspiciousLibraries() } catch (e: Exception) { true }
    }
    private fun checkUnexpectedDex(context: Context): Boolean {
        return try {
            val dirs = listOf(context.filesDir, context.cacheDir)
            dirs.any { dir -> dir.walkTopDown().maxDepth(3).any { it.isFile && (it.name.endsWith(".dex") || it.name.endsWith(".jar")) && !it.absolutePath.contains("app_flutter") && !it.absolutePath.contains("code_cache") } }
        } catch (e: Exception) { true }
    }
    private fun checkSuspiciousLibraries(): Boolean {
        return try {
            val content = File("/proc/self/maps").readText()
            listOf("inject", "payload", "exploit", "backdoor", "trojan", "keylog").any { content.contains(it, ignoreCase = true) }
        } catch (e: Exception) { true }
    }
    fun getSuspiciousModules(): String {
        return try {
            val suspicious = mutableListOf<String>()
            File("/proc/self/maps").readLines().forEach { line ->
                if (listOf("inject", "payload", "exploit").any { line.contains(it, ignoreCase = true) }) suspicious.add(line.split(" ").last())
            }
            suspicious.joinToString(",")
        } catch (e: Exception) { "" }
    }
}
