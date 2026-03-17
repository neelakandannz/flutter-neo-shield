package com.neelakandan.flutter_neo_shield.rasp

/**
 * Self-integrity checker that detects if our own RASP classes have been
 * tampered with by hook frameworks (Xposed, LSPosed, Frida, etc.).
 *
 * This runs before returning any RASP result to ensure the detection
 * code itself has not been bypassed.
 */
object SelfIntegrityChecker {

    /**
     * Returns true if hooking/tampering of our own classes is detected.
     */
    fun isHooked(): Boolean {
        return checkClassLoaderChain() ||
               checkStackTraceForHooks() ||
               checkClassHierarchy()
    }

    /**
     * Check 1: Verify our classes are loaded through a standard classloader.
     *
     * Xposed/LSPosed replace the classloader to intercept method calls.
     * A non-standard classloader in our chain indicates injection.
     */
    private fun checkClassLoaderChain(): Boolean {
        try {
            val ourClass = SelfIntegrityChecker::class.java
            var loader = ourClass.classLoader

            val standardLoaders = setOf(
                "dalvik.system.PathClassLoader",
                "dalvik.system.DexClassLoader",
                "dalvik.system.BaseDexClassLoader",
                "dalvik.system.InMemoryDexClassLoader",
                "java.lang.BootClassLoader"
            )

            var depth = 0
            while (loader != null && depth < 10) {
                val loaderName = loader.javaClass.name
                if (loaderName !in standardLoaders) {
                    // Non-standard classloader detected — likely Xposed/LSPosed
                    return true
                }
                loader = loader.parent
                depth++
            }
        } catch (e: Exception) {
            // Fail-closed: if we can't inspect classloader, assume hooked
            return true
        }
        return false
    }

    /**
     * Check 2: Inspect the current thread's stack trace for known hook
     * framework classes.
     *
     * When a hook framework intercepts a method, its classes appear
     * in the call stack. We check for Xposed, LSPosed, Substrate,
     * and Frida bridge classes.
     */
    private fun checkStackTraceForHooks(): Boolean {
        try {
            val stackTrace = Thread.currentThread().stackTrace

            val hookIndicators = arrayOf(
                "de.robv.android.xposed",
                "com.saurik.substrate",
                "org.lsposed",
                "io.github.lsposed",
                "com.elderdrivers.riru",
                "me.weishu.epic",
                "me.weishu.exp",
                "com.swift.sandhook",
                "pine.internal",
                "top.canyie.pine",
                "com.taichi",
                "EdXposed"
            )

            for (element in stackTrace) {
                val className = element.className
                for (indicator in hookIndicators) {
                    if (className.contains(indicator, ignoreCase = true)) {
                        return true
                    }
                }
            }
        } catch (e: Exception) {
            // Fail-closed
            return true
        }
        return false
    }

    /**
     * Check 3: Verify our detector classes have not been subclassed or
     * had unexpected superclasses injected.
     *
     * Some hook frameworks create proxy subclasses to override methods.
     * Our detector classes should have exactly java.lang.Object as their
     * superclass (or the expected Kotlin superclass).
     */
    private fun checkClassHierarchy(): Boolean {
        try {
            val criticalClasses = arrayOf(
                RootDetector::class.java,
                HookDetector::class.java,
                FridaDetector::class.java,
                DebuggerDetector::class.java,
                IntegrityDetector::class.java,
                NativeDebugDetector::class.java
            )

            for (clazz in criticalClasses) {
                val superclass = clazz.superclass
                // All our detector classes extend Object directly
                if (superclass != null && superclass.name != "java.lang.Object") {
                    return true
                }

                // Check for unexpected interfaces (hook frameworks may inject proxy interfaces)
                val interfaces = clazz.interfaces
                if (interfaces.isNotEmpty()) {
                    return true
                }
            }
        } catch (e: Exception) {
            // Fail-closed
            return true
        }
        return false
    }
}
