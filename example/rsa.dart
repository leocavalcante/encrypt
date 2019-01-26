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
  final encrypter = Encrypter(RSA(publicKey: publicKey, privateKey: privateKey));

  final encrypted = encrypter.encrypt(plainText);
  final decrypted = encrypter.decrypt(encrypted);

  print(decrypted); // Lorem ipsum dolor sit amet, consectetur adipiscing elit
  print(encrypted.bytes);
  print(encrypted.base16);
  print(encrypted
      .base64); // XWMuHTeO86gC6SsUh14h+jc4iQW7Vy0TDaBKN926QWhg5c3KKoSuF+6uedLWBEis0LYgTON2rhtTOjmb6bU2P27lgf+5JKdLGKqri2F4sCS3+/p/EPb41f60vnr3whX2o5VRJhJagxtrq0V3eu3X4UeRiO2y7yOt6MXyJxMFcXs=
}
