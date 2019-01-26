import 'dart:convert';
import 'dart:io';

import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:test/test.dart';

void main() {
  final text = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';
  final key = 'my32lengthsupersecretnooneknows1';
  final iv = '8bytesiv';

  group('AES', () {
    final encoded =
        'IBMwG6ieh/V/fNn6roa9CLdRmcHZA87XqjxIus92ZcmNMd7kURgARgFmbrvRpmdm9aX3iCT4I1us5GT6VSDVZw==';

    final encrypter = Encrypter(AES(key));
    final encrypted = Encrypted(base64.decode(encoded));

    test('encrypt', () => expect(encrypter.encrypt(text), equals(encrypted)));

    test('decrypt', () => expect(encrypter.decrypt(encrypted), equals(text)));
  });

  group('Salsa20', () {
    final encoded =
        'XY2uJh1aK1lgWVqUgPGBVr+tXzbAfAWuWaRocNnLEwXSUCo7NfP8HRl3wke+51QAaO+neShBYQ==';

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

    final encrypter = Encrypter(RSA(publicKey: publicKey, privateKey: privateKey));
    final encrypted = encrypter.encrypt(text);

    test('encrypt/decrypt',
        () => expect(encrypter.decrypt(encrypted), equals(text)));

    group('StateError', () {
      final badStateEncrypter = Encrypter(RSA());

      test('encrypt', () => expect(() => badStateEncrypter.encrypt(text), throwsStateError));

      test('decrypt', () => expect(() => badStateEncrypter.decrypt(encrypted), throwsStateError));
    });
  });
}
