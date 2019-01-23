import 'package:encrypt/encrypt.dart';

void main() {
  final key = 'my 32 length key................';
  final encrypter = Encrypter(AES(key));
  final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';

  final encrypted = encrypter.encrypt(plainText);
  final decrypted = encrypter.decrypt(encrypted);

  print(decrypted); // Lorem ipsum dolor sit amet, consectetur adipiscing elit
  print(encrypted.bytes);
  print(encrypted.base16);
  print(encrypted
      .base64); // FFyykKoJhWA+A23eeE8aUNhOgVBQfhIAHNY1YkO9ztlc9uFMCP+HtiMpc/ZBFVsycHwO6CmpWaVP2qLwpj91gQ==
}
