import '../lib/encrypt.dart';

void main() {
  final plainText =
      'hello'; //'Lorem ipsum dolor sit amet, consectetur adipiscing elit';

  final encrypter = Encrypter(Ripemd128());

  final encrypted = encrypter.encrypt(plainText);
  print(plainText);
  print(encrypted.bytes);
  print(encrypted.base16);
  print(encrypted.base64);
}
