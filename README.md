# encrypt

[![Pub Package](https://img.shields.io/pub/v/encrypt.svg)](https://pub.dartlang.org/packages/encrypt)
[![Build Status](https://travis-ci.org/leocavalcante/encrypt.svg?branch=master)](https://travis-ci.org/leocavalcante/encrypt)
[![Donate](https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=E4F45BFVMFVQW)

A set of high-level APIs over PointyCastle for two-way cryptography.

> Looking for password hashing? Please, visit [password](https://github.com/leocavalcante/password-dart).

## AES
```dart
import 'package:encrypt/encrypt.dart';

void main() {
  final key = 'my 32 length key................';
  final encrypter = Encrypter(AES(key));
  final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';

  final encrypted = encrypter.encrypt(plainText);
  final decrypted = encrypter.decrypt(encrypted);

  print(decrypted); // Lorem ipsum dolor sit amet, consectetur adipiscing elit
  print(encrypted.base64); // FFyykKoJhWA+A23eeE8aUNhOgVBQfhIAHNY1YkO9ztlc9uFMCP+HtiMpc/ZBFVsycHwO6CmpWaVP2qLwpj91gQ==
}
```

## RSA
```dart
import 'dart:io';
import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/asymmetric/api.dart';

void main() {
  final publicKeyFile = File('/path/to/public_key.pem');
  final privateKeyFile = File('/path/to/private_key.pem');

  final parser = RSAKeyParser();
  final RSAPublicKey publicKey = parser.parse(publicKeyFile.readAsStringSync());
  final RSAPrivateKey privateKey = parser.parse(privateKeyFile.readAsStringSync());

  final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';
  final encrypter = Encrypter(RSA(publicKey, privateKey));

  final encrypted = encrypter.encrypt(plainText);
  final decrypted = encrypter.decrypt(encrypted);

  print(decrypted); // Lorem ipsum dolor sit amet, consectetur adipiscing elit
  print(encrypted.base64); // XWMuHTeO86gC6SsUh14h+jc4iQW7Vy0TDaBKN926QWhg5c3KKoSuF+6uedLWBEis0LYgTON2rhtTOjmb6bU2P27lgf+5JKdLGKqri2F4sCS3+/p/EPb41f60vnr3whX2o5VRJhJagxtrq0V3eu3X4UeRiO2y7yOt6MXyJxMFcXs=
}

```

## Salsa20
```dart
import 'package:encrypt/encrypt.dart';

void main() {
  final key = 'my 32 length key................';
  final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';
  final iv = '8bytesiv'; // https://en.wikipedia.org/wiki/Initialization_vector
  final encrypter = Encrypter(Salsa20(key, iv));

  final encrypted = encrypter.encrypt(plainText);
  final decrypted = encrypter.decrypt(encrypted);

  print(decrypted); // Lorem ipsum dolor sit amet, consectetur adipiscing elit
  print(encrypted.base64); //63MQFprZ03mYQnPJuFn51+SzSAF4C9ixTFcKVUU0lKeT8FlU/I+arBU6knKK//in2z2eQiNEAw==
}
```
