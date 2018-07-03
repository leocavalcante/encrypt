import 'package:encrypt/encrypt.dart';
import 'package:test/test.dart';

void main() {
  final key = 'my32lengthsupersecretnooneknows1';
  final iv = '8bytesiv';

  group('AES', () {
    final encrypter = new Encrypter(new AES(key));

    final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit '
        .padRight(64, '.');
    final cipherText =
        'db066ce180f62f020617eb720b891c1efcc48b217cb83272812a8efe3b30e7eae4373ddcede4ea77bdae77d126d95457b3759b1983bf4cb4a6a5b051a5690bdf';

    test('encrypt',
        () => expect(encrypter.encrypt(plainText), equals(cipherText)));

    test('decrypt',
        () => expect(encrypter.decrypt(cipherText), equals(plainText)));
  });

  group('Salsa20', () {
    final encrypter = new Encrypter(new Salsa20(key, iv));

    final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';
    final cipherText =
        '5d8dae261d5a2b5960595a9480f18156bfad5f36c07c05ae59a46870d9cb1305d2502a3b35f3fc1d1977c247bee7540068efa779284161';

    test('encrypt',
        () => expect(encrypter.encrypt(plainText), equals(cipherText)));

    test('decrypt',
        () => expect(encrypter.decrypt(cipherText), equals(plainText)));
  });
}
