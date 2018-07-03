library encrypt;

export 'src/aes.dart';
export 'src/salsa20.dart';

abstract class Algorithm {
  String encrypt(String plainText);
  String decrypt(String cipherText);
}

class Encrypter {
  final Algorithm algo;

  Encrypter(this.algo);

  String encrypt(String plainText) {
    return algo.encrypt(plainText);
  }

  String decrypt(String cipherText) {
    return algo.decrypt(cipherText);
  }
}
