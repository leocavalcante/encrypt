library encrypt;

import 'dart:convert' as convert;
import 'dart:typed_data';

import 'package:collection/collection.dart';

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
  Encrypted(this._bytes);

  final Uint8List _bytes;

  /// Creates an Encrypted object from a hexdecimal string.
  Encrypted.fromBase16(String encoded)
      : _bytes = Uint8List.fromList(
          List.generate(encoded.length,
                  (i) => i % 2 == 0 ? encoded.substring(i, i + 2) : null)
              .where((b) => b != null)
              .map((b) => int.parse(b, radix: 16))
              .toList(),
        );

  /// Creates an Encrypted object from a Base64 string.
  Encrypted.fromBase64(String encoded)
      : _bytes = convert.base64.decode(encoded);

  /// Creates an Encrypted object from a UTF-8 string.
  Encrypted.fromUtf8(String input)
      : _bytes = Uint8List.fromList(convert.utf8.encode(input));

  /// Creates an Encrypted object from a length.
  Encrypted.fromLength(int length) : _bytes = Uint8List(length);

  /// Gets the Encrypted bytes.
  Uint8List get bytes => _bytes;

  /// Gets the Encrypted bytes as a Hexdecimal representation.
  String get base16 =>
      _bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

  /// Gets the Encrypted bytes as a Base64 representation.
  String get base64 => convert.base64.encode(_bytes);

  @override
  bool operator ==(other) {
    if (other is Encrypted) {
      return const ListEquality().equals(bytes, other.bytes);
    }

    return false;
  }
}

/// Represents an Initialization Vector.
class IV extends Encrypted {
  IV(Uint8List bytes) : super(bytes);
  IV.fromBase16(String encoded) : super.fromBase16(encoded);
  IV.fromBase64(String encoded) : super.fromBase64(encoded);
  IV.fromUtf8(String input) : super.fromUtf8(input);
  IV.fromLength(int length) : super.fromLength(length);
}

/// Represents an Encryption Key.
class Key extends Encrypted {
  Key(Uint8List bytes) : super(bytes);
  Key.fromBase16(String encoded) : super.fromBase16(encoded);
  Key.fromBase64(String encoded) : super.fromBase64(encoded);
  Key.fromUtf8(String input) : super.fromUtf8(input);
  Key.fromLength(int length) : super.fromLength(length);
}
