/// Configuration for the Log Shield module.
library;

/// Configuration for the [LogShield] module.
///
/// Controls log output behavior including release mode suppression,
/// redaction notices, and custom output handlers.
///
/// ```dart
/// final config = LogShieldConfig(
///   silentInRelease: true,
///   showRedactionNotice: true,
///   outputHandler: (message, level) => myLogger.log(message),
/// );
/// ```
class LogShieldConfig {
  /// Creates a [LogShieldConfig] with the specified options.
  const LogShieldConfig({
    this.sanitizeInDebug = false,
    this.silentInRelease = true,
    this.silentInProfile = false,
    this.showRedactionNotice = false,
    this.outputHandler,
    this.timestampFormat,
    this.enabledLevels = const {},
  });

  /// Whether to sanitize (hide PII) in debug mode.
  ///
  /// - `false` (default): During development, `shieldLog()` shows all real
  ///   values for easy debugging. No PII is hidden.
  /// - `true`: PII is hidden even in debug mode (useful for screenshots,
  ///   screen recordings, or team demos).
  ///
  /// In **release mode**, logs are always sanitized (or silenced if
  /// [silentInRelease] is true). This flag only affects debug/development.
  final bool sanitizeInDebug;

  /// If true, suppress all log output in release mode.
  final bool silentInRelease;

  /// If true, suppress all log output in profile mode.
  final bool silentInProfile;

  /// If true, appends a redaction notice showing how many items were redacted.
  final bool showRedactionNotice;

  /// Optional callback to route sanitized logs to a custom logger.
  ///
  /// When set, sanitized messages are passed to this function instead
  /// of being printed to the console.
  ///
  /// ```dart
  /// outputHandler: (message, level) {
  ///   myLogger.log(level, message);
  /// },
  /// ```
  final void Function(String sanitizedMessage, String level)? outputHandler;

  /// Optional timestamp format string to prepend to log lines.
  ///
  /// If set, each log line will be prefixed with the current timestamp.
  final String? timestampFormat;

  /// Set of log levels to output. Empty set means all levels are enabled.
  ///
  /// ```dart
  /// enabledLevels: {'INFO', 'ERROR', 'WARNING'},
  /// ```
  final Set<String> enabledLevels;

  /// Returns whether the given [level] is enabled.
  bool isLevelEnabled(String level) =>
      enabledLevels.isEmpty || enabledLevels.contains(level.toUpperCase());
}
