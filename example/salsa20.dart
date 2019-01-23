import 'package:encrypt/encrypt.dart';

void main() {
  final key = 'my 32 length key................';
  final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';
  final iv = '8bytesiv'; // https://en.wikipedia.org/wiki/Initialization_vector
  final encrypter = Encrypter(Salsa20(key, iv));

  final encrypted = encrypter.encrypt(plainText);
  final decrypted = encrypter.decrypt(encrypted);

  print(decrypted); // Lorem ipsum dolor sit amet, consectetur adipiscing elit
  print(encrypted.bytes);
  print(encrypted.base16);
  print(encrypted
      .base64); //63MQFprZ03mYQnPJuFn51+SzSAF4C9ixTFcKVUU0lKeT8FlU/I+arBU6knKK//in2z2eQiNEAw==
}
