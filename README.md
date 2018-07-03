# encrypt

[![Pub Package](https://img.shields.io/pub/v/encrypt.svg)](https://pub.dartlang.org/packages/encrypt)
[![Build Status](https://travis-ci.org/leocavalcante/encrypt.svg?branch=master)](https://travis-ci.org/leocavalcante/encrypt)

A set of high-level APIs over PointyCastle for two-way cryptography.

> Looking for password hashing? Please, visit [password](https://github.com/leocavalcante/password-dart).

## AES (Block Cipher)
```dart
import 'package:encrypt/encrypt.dart';

void main() {
  final key = 'my32lengthsupersecretnooneknows1';

  final encrypter = new Encrypter(new AES(key));
  final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit ........';

  final encryptedText = encrypter.encrypt(plainText);
  final decryptedText = encrypter.decrypt(encryptedText);

  print(encryptedText); // db066ce180f62f020617eb720b891c1efcc48b217cb83272812a8efe3b30e7eae4373ddcede4ea77bdae77d126d95457b3759b1983bf4cb4a6a5b051a5690bdf
  print(decryptedText); // Lorem ipsum dolor sit amet, consectetur adipiscing elit ........
}
```

## Salsa20 (Stream Cipher)
```dart
import 'package:encrypt/encrypt.dart';

void main() {
  final key = 'private!!!!!!!!!';
  final iv = '8bytesiv'; // https://en.wikipedia.org/wiki/Initialization_vector
  final plainText = 'Secret';

  final encrypter = new Encrypter(new Salsa20(key, iv));

  final encrypted = encrypter.encrypt(plainText);
  final decrypted = encrypter.decrypt(encrypted);

  print(encrypted); // c5cc91943cf0
  print(decrypted); // Secret
}
```

## RSA (Asymmetric)
TODO
