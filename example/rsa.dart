import 'dart:io';

import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/asymmetric/api.dart';

void main() {
  final publicKeyFile = File('test/public.pem');
  final privateKeyFile = File('test/private.pem');

  final parser = RSAKeyParser();

  final publicKey =
      parser.parse(publicKeyFile.readAsStringSync()) as RSAPublicKey;
  final privateKey =
      parser.parse(privateKeyFile.readAsStringSync()) as RSAPrivateKey;

  final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';
  final encrypter =
      Encrypter(RSA(publicKey: publicKey, privateKey: privateKey));

  final encrypted = encrypter.encrypt(plainText);
  final decrypted = encrypter.decrypt(encrypted);

  print(decrypted);
  print(encrypted.bytes);
  print(encrypted.base16);
  print(encrypted.base64);
}
