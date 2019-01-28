import 'package:encrypt/encrypt.dart';

void main() {
  final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';

  final key = Key.fromLength(32);
  final iv = IV.fromLength(16);
  final encrypter = Encrypter(AES(key, iv));

  final encrypted = encrypter.encrypt(plainText);
  final decrypted = encrypter.decrypt(encrypted);

  print(decrypted);
  print(encrypted.bytes);
  print(encrypted.base16);
  print(encrypted.base64);
}
