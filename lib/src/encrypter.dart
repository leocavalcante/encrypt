part of encrypt;

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
