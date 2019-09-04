import 'package:encrypt/encrypt.dart';
import 'package:encrypt/encrypt_io.dart';
import 'package:pointycastle/asymmetric/api.dart';

void main() async {
  final publicKey = await parseKeyFromFile<RSAPublicKey>('test/public.pem');
  final privKey = await parseKeyFromFile<RSAPrivateKey>('test/private.pem');

  final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';
  final encrypter = Encrypter(RSA(publicKey: publicKey, privateKey: privKey));

  final encrypted = encrypter.encrypt(plainText);
  final decrypted = encrypter.decrypt(encrypted);

  print(decrypted);
  print(encrypted.bytes);
  print(encrypted.base16);
  print(encrypted.base64);
}
