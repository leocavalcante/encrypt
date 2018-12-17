library encrypt;

export 'src/aes.dart';
export 'src/salsa20.dart';

/// Interface for the Algorithms.
abstract class Algorithm {
  /// Encrypt [plainText] to a hexdecimal representation.
  String encrypt(String plainText);

  /// Dencrypt [cipherText] from a hexdecimal representation.
  String decrypt(String cipherText);
}

/// Wraps Algorithms in a unique Container.
class Encrypter {
  final Algorithm algo;

  Encrypter(this.algo);

  /// Calls [encrypt] on the wrapped Algorithm.
  String encrypt(String plainText) {
    return algo.encrypt(plainText);
  }

  /// Calls [decrypt] on the wrapped Algorithm.
  String decrypt(String cipherText) {
    return algo.decrypt(cipherText);
  }
}
