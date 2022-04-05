import 'package:encrypt/encrypt.dart';
import 'package:test/test.dart';

void main() {
  group('Battle test', () {
    test('Emoji', () {
      const encoded = 'iPC4DII05qnIJsFm6/RUp6OQEnvLSTq1pW+4/cjHf4c=';
      final encrypter = Encrypter(AES(Key.allZerosOfLength(32)));

      expect(
          Encrypted.fromBase64(encoded),
          equals(
            encrypter.encrypt('Text to encrypt 😀', iv: IV.allZerosOfLength(16))));
    });
  });
}
