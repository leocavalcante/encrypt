import 'package:encrypt/encrypt.dart';
import 'package:encrypt/encrypt_io.dart';
import 'package:pointycastle/export.dart' hide Signer hide RSASigner;
import 'package:test/test.dart';

void main() {
  test('Signer', () async {
    final publicKey = await parseKeyFromFile<RSAPublicKey>('test/public.pem');
    final privateKey =
        await parseKeyFromFile<RSAPrivateKey>('test/private.pem');
    final signer = Signer(RSASigner(RSASignDigest.SHA256,
        publicKey: publicKey, privateKey: privateKey));

    final message = 'hello world';
    final digest =
        'jfMhNM2v6hauQr6w3ji0xNOxGInHbeIH3DHlpf2W3vmSMyAuwGHG0KLcunggG4XtZrZPAib7oHaKEAdkHaSIGXAtEqaAvocq138oJ7BEznA4KVYuMcW9c8bRy5E4tUpikTpoO+okHdHr5YLc9y908CAQBVsfhbt0W9NClvDWegs=';
    final externalDigest =
        'YSBH0/A2uMS/fr74LK//yBxe6oBV/IlENLEebbBx/I6WSizcVqb2BGDwWy6yu1hJ+DG6c1VgUvYgaR2jGRCdWidOeipkfSza+9+5wl4s/rtIDJjCjq65+GazlZLsakDTUDc75KK1qHeoardUIPYHh+L0jZrzrgRlUASG8uyr7BU=';

    expect(signer.sign(message).base64, equals(digest));
    expect(signer.verify(message, Encrypted.from64(digest)), isTrue);
    expect(
        signer.verify(message,
            Encrypted.from64('eW91J3JlIHZlcnkgY3VyaW91cywgYXJlbid0IHlvdT8=')),
        isFalse);
    expect(signer.verify('test', Encrypted.from64(externalDigest)), isTrue);
  });
}
