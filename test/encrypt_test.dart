import 'dart:convert';
import 'dart:io';

import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:test/test.dart';

void main() {
  final text = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';
  final key = 'my32lengthsupersecretnooneknows1';
  final iv = IV.fromLength(8);

  group('AES', () {
    final encoded =
        'DIXikIUegcvoS6qSszWXgGkVga1GE6a+WkO24Srn1xtc9wtqN4QzWen95c7w2vy7NzMs+fQGPgQ5e/WesjaSng==';

    final encrypter = Encrypter(AES(key, iv));
    final encrypted = Encrypted(base64.decode(encoded));

    test('encrypt', () => expect(encrypter.encrypt(text), equals(encrypted)));

    test('decrypt', () => expect(encrypter.decrypt(encrypted), equals(text)));
  });

  group('Salsa20', () {
    final encoded =
        '2FCmbbVYQrbLn8pkyPe4mt0ooqNRA8Dm9EmzZVSWgW+M/6FembxLmVdt9/JJt+NSMnx1hNjuOw==';

    final encrypter = Encrypter(Salsa20(key, iv));
    final encrypted = Encrypted(base64.decode(encoded));

    test('encrypt', () => expect(encrypter.encrypt(text), equals(encrypted)));

    test('decrypt', () => expect(encrypter.decrypt(encrypted), equals(text)));
  });

  group('RSA', () {
    final parser = RSAKeyParser();

    final RSAPublicKey publicKey =
        parser.parse(File('test/public.pem').readAsStringSync());
    final RSAPrivateKey privateKey =
        parser.parse(File('test/private.pem').readAsStringSync());

    final encrypter =
        Encrypter(RSA(publicKey: publicKey, privateKey: privateKey));
    final encrypted = encrypter.encrypt(text);

    test('encrypt/decrypt',
        () => expect(encrypter.decrypt(encrypted), equals(text)));

    group('StateError', () {
      final badStateEncrypter = Encrypter(RSA());

      test(
          'encrypt',
          () =>
              expect(() => badStateEncrypter.encrypt(text), throwsStateError));

      test(
          'decrypt',
          () => expect(
              () => badStateEncrypter.decrypt(encrypted), throwsStateError));
    });
  });
}
