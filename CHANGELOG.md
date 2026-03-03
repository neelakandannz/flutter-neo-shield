## 0.2.0

* String Shield: compile-time string obfuscation with @Obfuscate() annotation
* Three obfuscation strategies: XOR, Enhanced XOR, Split-and-reassemble
* build_runner integration with code generation
* Runtime deobfuscation with optional caching and stats tracking
* Removed shieldPrint() (use shieldLog() instead)

## 0.1.0

* Initial release
* Core PII Detection Engine with 11 built-in patterns
* Log Shield: shieldLog(), JSON sanitizer, Dio interceptor
* Clipboard Shield: secureCopy() with auto-clear, SecureCopyButton, SecurePasteField
* Memory Shield: SecureString, SecureBytes, SecureValue with wipe-on-dispose
* Platform channels for native memory wipe (Android/iOS)
* Full example app with demos for all features
* 90%+ test coverage
