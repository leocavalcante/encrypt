library encrypt;

import 'dart:typed_data';
import 'dart:convert' as convert;

export 'src/aes.dart';
export 'src/rsa.dart';
export 'src/salsa20.dart';

/// Interface for the Algorithms.
abstract class Algorithm {
  /// Encrypt [text] to a hexdecimal representation.
  Encrypted encrypt(String text);

  /// Decrypt [cipherText] from a hexdecimal representation.
  String decrypt(Encrypted encrypted);
}

/// Wraps Algorithms in a unique Container.
class Encrypter {
  final Algorithm algo;

  Encrypter(this.algo);

  /// Calls [encrypt] on the wrapped Algorithm.
  Encrypted encrypt(String text) {
    return algo.encrypt(text);
  }

  /// Calls [decrypt] on the wrapped Algorithm.
  String decrypt(Encrypted encrypted) {
    return algo.decrypt(encrypted);
  }
}

/// Represents an encripted value.
class Encrypted {
  final Uint8List bytes;

  Encrypted(this.bytes);

  /// Gets the encrypted bytes by a Hexdecimal representation.
  String get base16 =>
      bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

  /// Gets the encrypted bytes by a Base64  representation.
  String get base64 => convert.base64.encode(bytes);

  @override
  bool operator ==(other) {
    if (other is Encrypted) {
      return this.base64 == other.base64;
    }

    return false;
  }
}
