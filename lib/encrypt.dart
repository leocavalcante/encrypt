library encrypt;

import 'dart:convert';

import 'src/helpers.dart';

export 'src/aes.dart';
export 'src/rsa.dart';
export 'src/salsa20.dart';

/// Interface for the Algorithms.
abstract class Algorithm {
  /// Encrypt [plainText] to a hexdecimal representation.
  String encrypt(String plainText);

  /// Decrypt [cipherText] from a hexdecimal representation.
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

/// Swap bytes representation from hexdecimal to Base64.
String from16To64(String hex) {
  final bytes = createUint8ListFromHexString(hex);
  return base64.encode(bytes);
}

/// Swap bytes representation from Base64 to hexdecimal.
String from64To16(String encoded) {
  final bytes = base64.decode(encoded);
  return formatBytesAsHexString(bytes);
}
