import 'package:encrypt/encrypt.dart';
import 'package:encrypt/encrypt_io.dart';
import 'package:pointycastle/asymmetric/api.dart';

void main() async {
  final publicKey = await parseKeyFromFile<RSAPublicKey>('test/public.pem');
  final privKey = await parseKeyFromFile<RSAPrivateKey>('test/private.pem');
  final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';
  Encrypter encrypter;
  Encrypted encrypted;
  String decrypted;
  
  // PKCS1 (Default)
  encrypter = Encrypter(RSA(publicKey: publicKey, privateKey: privKey));
  encrypted = encrypter.encrypt(plainText);
  decrypted = encrypter.decrypt(encrypted);

  print('PKCS1 (Default)');
  print(decrypted);
  print(encrypted.bytes);
  print(encrypted.base16);
  print(encrypted.base64);

  // OAEP (SHA1)
  encrypter = Encrypter(
    RSA(publicKey: publicKey, privateKey: privKey, encoding: RSAEncoding.OAEP),
  );
  encrypted = encrypter.encrypt(plainText);
  decrypted = encrypter.decrypt(encrypted);

  print('\nOAEP (SHA1)');
  print(decrypted);
  print(encrypted.bytes);
  print(encrypted.base16);
  print(encrypted.base64);

  // OAEP (SHA256)
  encrypter = Encrypter(
    RSA(
      publicKey: publicKey,
      privateKey: privKey,
      encoding: RSAEncoding.OAEP,
      digest: RSADigest.SHA256,
    )
  );
  encrypted = encrypter.encrypt(plainText);
  decrypted = encrypter.decrypt(encrypted);

  print('\nOAEP (SHA256)');
  print(decrypted);
  print(encrypted.bytes);
  print(encrypted.base16);
  print(encrypted.base64);
}
