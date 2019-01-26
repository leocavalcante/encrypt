import 'package:encrypt/encrypt.dart';

void main() {
  final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';
  final key = 'my 32 length key................';
  final iv = IV.fromLength(16);

  final encrypter = Encrypter(AES(key, iv));

  final encrypted = encrypter.encrypt(plainText);
  final decrypted = encrypter.decrypt(encrypted);

  print(decrypted); // Lorem ipsum dolor sit amet, consectetur adipiscing elit
  print(encrypted.bytes);
  print(encrypted.base16);
  print(encrypted.base64); // R4PxiU3h8YoIRqVowBXm36ZcCeNeZ4s1OvVBTfFlZRdmohQqOpPQqD1YecJeZMAop/hZ4OxqgC1WtwvX/hP9mw==
}
