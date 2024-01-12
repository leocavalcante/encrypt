part of encrypt;

/// Represents an encripted value.
class Encrypted {
  /// Creates an Encrypted object from a Uint8List.
  Encrypted(this._bytes);

  final Uint8List _bytes;

  /// Creates an Encrypted object from a hexdecimal string.
  Encrypted.fromBase16(String encoded) : _bytes = decodeHexString(encoded);

  /// Creates an Encrypted object from a Base64 string.
  Encrypted.fromBase64(String encoded) : _bytes = convert.base64.decode(encoded);

  /// Creates an Encrypted object from a Base64Url string.
  Encrypted.fromBase64Url(String encoded) : _bytes = convert.base64Decode(encoded);

  /// Creates an Encrypted object from a Base64 string.
  Encrypted.from64(String encoded) : _bytes = convert.base64.decode(encoded);

  /// Creates an Encrypted object from a UTF-8 string.
  Encrypted.fromUtf8(String input) : _bytes = convert.utf8.encode(input);

  /// Creates an Encrypted object from a length.
  /// The key is filled with [length] bytes generated by a
  /// Random.secure() generator
  Encrypted.fromLength(int length) : _bytes = SecureRandom(length).bytes;

  /// Creates an Encrypted object from a length.
  /// The key is filled with [length] bytes generated by a
  /// Random.secure() generator
  Encrypted.fromSecureRandom(int length) : _bytes = SecureRandom(length).bytes;

  /// Creates an Encrypted object of ALL ZEROS from a length.
  /// The key is ALL ZEROS - NOT CRYPTOGRAPHICALLY SECURE!
  Encrypted.allZerosOfLength(int length) : _bytes = Uint8List(length);

  /// Gets the Encrypted bytes.
  Uint8List get bytes => _bytes;

  /// Gets the Encrypted bytes as a Hexdecimal representation.
  String get base16 => _bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

  /// Gets the Encrypted bytes as a Base64 representation.
  String get base64 => convert.base64.encode(_bytes);

  /// Gets the Encrypted bytes as a Base64Url representation.
  String get base64Url => convert.base64Url.encode(_bytes);

  @override
  bool operator ==(other) {
    if (other is Encrypted) {
      return const ListEquality().equals(bytes, other.bytes);
    }

    return false;
  }

  @override
  int get hashCode => ListEquality().hash(bytes);
}

/// Represents an Initialization Vector.
class IV extends Encrypted {
  /// Creates an Initialization Vector object from a Uint8List.
  IV(Uint8List bytes) : super(bytes);

  /// Creates an Initialization Vector object from a hexdecimal string.
  IV.fromBase16(String encoded) : super.fromBase16(encoded);

  /// Creates an Initialization Vector object from a Base64 string.
  IV.fromBase64(String encoded) : super.fromBase64(encoded);

  /// Creates an Initialization Vector object from a UTF-8 string.
  IV.fromUtf8(String input) : super.fromUtf8(input);

  /// Creates an Initialization Vector object from a length.
  /// The key is filled with [length] bytes generated by a
  /// Random.secure() generator
  IV.fromLength(int length) : super.fromLength(length);

  /// Creates an Initialization Vector object from a length.
  /// The key is filled with [length] bytes generated by a
  /// Random.secure() generator
  IV.fromSecureRandom(int length) : super(SecureRandom(length).bytes);

  /// Creates an Initialization Vector object of ALL ZEROS from a length.
  /// The key is ALL ZEROS - NOT CRYPTOGRAPHICALLY SECURE!
  IV.allZerosOfLength(int length) : super.allZerosOfLength(length);
}

/// Represents an Encryption Key.
class Key extends Encrypted {
  /// Creates an Encryption Key object from a Uint8List.
  Key(Uint8List bytes) : super(bytes);

  /// Creates an Encryption Key object from a hexdecimal string.
  Key.fromBase16(String encoded) : super.fromBase16(encoded);

  /// Creates an Encryption Key object from a Base64 string.
  Key.fromBase64(String encoded) : super.fromBase64(encoded);

  /// Creates an Encryption Key object from a UTF-8 string.
  Key.fromUtf8(String input) : super.fromUtf8(input);

  /// Creates an Encryption Key object from a length.
  /// The key is filled with [length] bytes generated by a
  /// Random.secure() generator
  Key.fromLength(int length) : super.fromLength(length);

  /// Creates an Encryption Key object from a length.
  /// The key is filled with [length] bytes generated by a
  /// Random.secure() generator
  Key.fromSecureRandom(int length) : super(SecureRandom(length).bytes);

  /// Creates an Encryption Key object of ALL ZEROS from a length.
  /// The key is ALL ZEROS - NOT CRYPTOGRAPHICALLY SECURE!
  Key.allZerosOfLength(int length) : super.allZerosOfLength(length);

  Key stretch(int desiredKeyLength, {int iterationCount = 100, Uint8List? salt}) {
    if (salt == null) {
      salt = SecureRandom(desiredKeyLength).bytes;
    }

    final params = Pbkdf2Parameters(salt, iterationCount, desiredKeyLength);
    final pbkdf2 = PBKDF2KeyDerivator(Mac('SHA-1/HMAC'))..init(params);

    return Key(pbkdf2.process(_bytes));
  }

  int get length => bytes.lengthInBytes;
}
