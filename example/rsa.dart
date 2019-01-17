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
