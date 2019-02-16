import 'package:encrypt/encrypt.dart';
import 'package:test/test.dart';

void main() {
  group('Battle test', () {
    test('Emoji', () {
      const encoded = 'iPC4DII05qnIJsFm6/RUp6OQEnvLSTq1pW+4/cjHf4c=';
      final encrypter = Encrypter(AES(Key.fromLength(32), IV.fromLength(16)));

      expect(Encrypted.fromBase64(encoded),
          equals(encrypter.encrypt('Text to encrypt 😀')));
    });
  });
}
