# encrypt

[![Pub Package](https://img.shields.io/pub/v/encrypt.svg)](https://pub.dartlang.org/packages/encrypt)
[![Build Status](https://travis-ci.org/leocavalcante/encrypt.svg?branch=master)](https://travis-ci.org/leocavalcante/encrypt)
[![Donate](https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=E4F45BFVMFVQW)

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

### Chinese example
```dart
import 'package:encrypt/encrypt.dart';

void main() {
  final key = '1234567890123456';
  final iv = '8bytesiv';
  final encryptor = Encrypter(Salsa20(key, iv));
  String text = '你好';
  String base64Text = base64.encode(utf8.encode(text));
  String encText  = encryptor.encrypt(base64Text);
  var decStr = utf8.decode(base64.decode(encryptor.decrypt(encText)));

  print('origin:'+text);//你好
  print('base64Text:'+base64Text);//5L2g5aW9
  print('enc text:'+encText);//c72f29fd34b15145
  print('dec text:'+decStr);//你好
}
```

## RSA+PKCS1 (Asymmetric)
```dart
import 'package:encrypt/encrypt.dart';
import 'dart:io';

import 'package:pointycastle/asymmetric/api.dart';

void main() {
  final publicKeyFile = File('test/public.pem');
  final privateKeyFile = File('test/private.pem');

  final parser = RSAKeyParser();

  final RSAPublicKey publicKey = parser.parse(publicKeyFile.readAsStringSync());
  final RSAPrivateKey privateKey =
      parser.parse(privateKeyFile.readAsStringSync());

  final encrypter = Encrypter(RSA(publicKey, privateKey));
  final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';

  final encryptedText = encrypter.encrypt(plainText);
  final decryptedText = encrypter.decrypt(encryptedText);

  print('Hexdecimal: $encryptedText');
  print('Base64: ${from16To64(encryptedText)}');
  print(decryptedText);
}
```
---
