import 'package:encrypt/encrypt.dart';

void main() {
  final key = 'private!!!!!!!!!';
  final iv = '8bytesiv'; // https://en.wikipedia.org/wiki/Initialization_vector
  final plainText = 'Secret';

  final encrypter = new Encrypter(new Salsa20(key, iv));

  final encrypted = encrypter.encrypt(plainText); // c5cc91943cf0
  final decrypted = encrypter.decrypt(encrypted); // Secret

  print(encrypted);
  print(decrypted);
}
