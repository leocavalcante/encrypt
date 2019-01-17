import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:test/test.dart';
import 'dart:io';

void main() {
  final key = 'my32lengthsupersecretnooneknows1';
  final iv = '8bytesiv';

  group('AES', () {
    final encrypter = Encrypter(AES(key));

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
    final encrypter = Encrypter(Salsa20(key, iv));

    final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';
    final cipherText =
        '5d8dae261d5a2b5960595a9480f18156bfad5f36c07c05ae59a46870d9cb1305d2502a3b35f3fc1d1977c247bee7540068efa779284161';

    test('encrypt',
        () => expect(encrypter.encrypt(plainText), equals(cipherText)));

    test('decrypt',
        () => expect(encrypter.decrypt(cipherText), equals(plainText)));
  });

  group('RSA', () {
    final parser = RSAKeyParser();

    final RSAPublicKey publicKey =
        parser.parse(File('test/public.pem').readAsStringSync());
    final RSAPrivateKey privateKey =
        parser.parse(File('test/private.pem').readAsStringSync());

    final encrypter = Encrypter(RSA(publicKey, privateKey));

    final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';
    final cipherText = encrypter.encrypt(plainText);

    test('encrypt',
        () => expect(encrypter.decrypt(cipherText), equals(plainText)));
  });
}
