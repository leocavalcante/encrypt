import 'package:encrypt/encrypt.dart';

void main() {
  final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';

  final key = Key.fromSecureRandom(32);
  final iv = IV.fromSecureRandom(16);
  final encrypter = Encrypter(AES(key));

  final encrypted = encrypter.encrypt(plainText, iv: iv);
  final decrypted = encrypter.decrypt(encrypted, iv: iv);

  print(decrypted);
  print(encrypted.bytes);
  print(encrypted.base16);
  print(encrypted.base64);
}
