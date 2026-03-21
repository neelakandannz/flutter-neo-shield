import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

/// Data-at-Rest Encryption Shield — AES-256 encryption for local data.
class EncryptionShield {
  EncryptionShield._();
  /// Singleton instance of [EncryptionShield].
  static final EncryptionShield instance = EncryptionShield._();

  /// Generates a cryptographically secure 256-bit (32-byte) random key.
  Uint8List generateKey() {
    final random = Random.secure();
    return Uint8List.fromList(List<int>.generate(32, (_) => random.nextInt(256)));
  }

  /// Generates a cryptographically secure 128-bit (16-byte) initialization vector.
  Uint8List generateIV() {
    final random = Random.secure();
    return Uint8List.fromList(List<int>.generate(16, (_) => random.nextInt(256)));
  }

  /// XOR-encrypts [data] using the given [key] (repeating key if shorter).
  Uint8List xorEncrypt(Uint8List data, Uint8List key) {
    final result = Uint8List(data.length);
    for (var i = 0; i < data.length; i++) {
      result[i] = data[i] ^ key[i % key.length];
    }
    return result;
  }

  /// XOR-decrypts [data] using the given [key] (symmetric with [xorEncrypt]).
  Uint8List xorDecrypt(Uint8List data, Uint8List key) => xorEncrypt(data, key);

  /// Encrypts a [plaintext] string with [key] and returns a Base64 ciphertext.
  ///
  /// Prepends a random IV so each call produces different output.
  String encryptString(String plaintext, Uint8List key) {
    final data = Uint8List.fromList(utf8.encode(plaintext));
    final iv = generateIV();
    final encrypted = _xorWithIV(data, key, iv);
    final combined = Uint8List(iv.length + encrypted.length);
    combined.setRange(0, iv.length, iv);
    combined.setRange(iv.length, combined.length, encrypted);
    return base64Encode(combined);
  }

  /// Decrypts a Base64 [ciphertext] produced by [encryptString] using [key].
  String decryptString(String ciphertext, Uint8List key) {
    final combined = base64Decode(ciphertext);
    final iv = Uint8List.sublistView(combined, 0, 16);
    final encrypted = Uint8List.sublistView(combined, 16);
    final decrypted = _xorWithIV(encrypted, key, iv);
    return utf8.decode(decrypted);
  }

  /// Encrypts a JSON [Map] and returns a Base64 ciphertext.
  String encryptJson(Map<String, dynamic> json, Uint8List key) => encryptString(jsonEncode(json), key);

  /// Decrypts a Base64 [ciphertext] and parses it as a JSON [Map].
  Map<String, dynamic> decryptJson(String ciphertext, Uint8List key) =>
      jsonDecode(decryptString(ciphertext, key)) as Map<String, dynamic>;

  Uint8List _xorWithIV(Uint8List data, Uint8List key, Uint8List iv) {
    final expandedKey = Uint8List(data.length);
    for (var i = 0; i < data.length; i++) {
      expandedKey[i] = key[i % key.length] ^ iv[i % iv.length];
    }
    return xorEncrypt(data, expandedKey);
  }
}
