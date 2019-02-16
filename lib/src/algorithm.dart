part of encrypt;

/// Interface for the Algorithms.
abstract class Algorithm {
  /// Encrypt [bytes].
  Encrypted encrypt(Uint8List bytes);

  /// Decrypt [encrypted] value.
  Uint8List decrypt(Encrypted encrypted);
}
