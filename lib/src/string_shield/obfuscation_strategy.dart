/// Obfuscation strategies for compile-time string protection.
library;

/// The strategy used to obfuscate a string at compile time.
///
/// Each strategy provides a different trade-off between performance
/// and resistance to reverse engineering.
///
/// ```dart
/// @Obfuscate(strategy: ObfuscationStrategy.enhancedXor)
/// static const String apiKey = 'sk_live_abc123';
/// ```
enum ObfuscationStrategy {
  /// XOR each UTF-8 byte with a random key.
  ///
  /// Fast and effective against the `strings` command.
  /// Suitable for most use cases.
  xor,

  /// XOR + reverse byte order + random junk byte insertion.
  ///
  /// More resistant to pattern analysis than plain XOR.
  /// Slightly more runtime overhead due to junk removal.
  enhancedXor,

  /// Split the string into N chunks stored in separate arrays.
  ///
  /// Chunks are stored out of order with a reassembly index.
  /// Makes it difficult to reconstruct the original string even
  /// if individual chunks are found in the binary.
  split,
}
