import 'package:encrypt/encrypt.dart';

void main() {
  final key = 'my32lengthsupersecretnooneknows1';

  final encrypter = Encrypter(AES(key));
  final plainText =
      'Lorem ipsum dolor sit amet, consectetur adipiscing elit ........';

  final encryptedText = encrypter.encrypt(plainText);
  final decryptedText = encrypter.decrypt(encryptedText);

  print(
      encryptedText); // db066ce180f62f020617eb720b891c1efcc48b217cb83272812a8efe3b30e7eae4373ddcede4ea77bdae77d126d95457b3759b1983bf4cb4a6a5b051a5690bdf
  print(
      decryptedText); // Lorem ipsum dolor sit amet, consectetur adipiscing elit ........
}
