import 'package:encrypt/encrypt.dart';
import 'package:test/test.dart';

void main() {
  group('AES', () {
    final key = 'my32lengthsupersecretnooneknows1';

    final encrypter = new Encrypter(new AES(key));
    final plainText =
        'Lorem ipsum dolor sit amet, consectetur adipiscing elit ........';
    final cipherText =
        'db066ce180f62f020617eb720b891c1efcc48b217cb83272812a8efe3b30e7eae4373ddcede4ea77bdae77d126d95457b3759b1983bf4cb4a6a5b051a5690bdf';

    test('encrypt',
        () => expect(encrypter.encrypt(plainText), equals(cipherText)));

    test('decrypt',
        () => expect(encrypter.decrypt(cipherText), equals(plainText)));
  });
}
