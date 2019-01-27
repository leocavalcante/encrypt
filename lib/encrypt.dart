library encrypt;

import 'dart:convert' as convert;
import 'dart:typed_data';

export 'src/aes.dart';
export 'src/rsa.dart';
export 'src/salsa20.dart';

/// Interface for the Algorithms.
abstract class Algorithm {
  /// Encrypt [bytes].
  Encrypted encrypt(Uint8List bytes);

  /// Decrypt [encrypted] value.
  Uint8List decrypt(Encrypted encrypted);
}

/// Wraps Algorithms in a unique Container.
class Encrypter {
  final Algorithm algo;

  Encrypter(this.algo);

  /// Calls [encrypt] on the wrapped Algorithm.
  Encrypted encrypt(String input) {
    return algo.encrypt(Uint8List.fromList(convert.utf8.encode(input)));
  }

  /// Calls [decrypt] on the wrapped Algorithm.
  String decrypt(Encrypted encrypted) {
    return convert.utf8.decode(algo.decrypt(encrypted), allowMalformed: true);
  }

  /// Sugar for `decrypt(Encrypted.fromBase16(encoded))`.
  String decrypt16(String encoded) {
    return decrypt(Encrypted.fromBase16(encoded));
  }

  /// Sugar for `decrypt(Encrypted.fromBase64(encoded))`.
  String decrypt64(String encoded) {
    return decrypt(Encrypted.fromBase64(encoded));
  }
}

/// Represents an encripted value.
class Encrypted {
  final Uint8List bytes;

  Encrypted(this.bytes);

  /// Creates an Encrypted object from a hexdecimal string.
  Encrypted.fromBase16(String encoded)
      : bytes = _createUint8ListFromHexString(encoded);

  /// Creates an Encrypted object from a Base64 string.
  Encrypted.fromBase64(String encoded) : bytes = convert.base64.decode(encoded);

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

/// Represents an Initialization Vector.
class IV {
  final Uint8List bytes;

  IV(this.bytes);

  /// Sugar for IV(Uint8List(length)).
  IV.fromLength(int length) : bytes = Uint8List(length);

  /// Creates an IV using a hexdecimal string.
  IV.fromBase16(String encoded)
      : bytes = _createUint8ListFromHexString(encoded);

  /// Creates an IV using a Base64 encoded string.
  IV.fromBase64(String encoded) : bytes = convert.base64.decode(encoded);
}

Uint8List _createUint8ListFromHexString(String hex) {
  var result = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < hex.length; i += 2) {
    var num = hex.substring(i, i + 2);
    var byte = int.parse(num, radix: 16);
    result[i ~/ 2] = byte;
  }
  return result;
}
