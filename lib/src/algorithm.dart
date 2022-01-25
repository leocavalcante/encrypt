part of encrypt;

/// Interface for the Algorithms.
abstract class Algorithm {
  /// Encrypt [bytes].
  Encrypted encrypt(Uint8List bytes, {IV? iv, Uint8List? associatedData});

  /// Decrypt [encrypted] value.
  Uint8List decrypt(Encrypted encrypted, {IV? iv, Uint8List? associatedData});
}

/// Interface for the signing algorithms
abstract class SignerAlgorithm {
  /// Sign [bytes].
  Encrypted sign(Uint8List bytes);

  /// Verify [encrypted] signature.
  bool verify(Uint8List bytes, Encrypted encrypted);
}
