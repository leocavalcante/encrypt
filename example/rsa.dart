import 'dart:io';

import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/asymmetric/api.dart';

void main() {
  final publicKeyFile = File('test/public.pem');
  final privateKeyFile = File('test/private.pem');

  final parser = RSAKeyParser();

  final RSAPublicKey publicKey = parser.parse(publicKeyFile.readAsStringSync());
  final RSAPrivateKey privateKey =
      parser.parse(privateKeyFile.readAsStringSync());

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
