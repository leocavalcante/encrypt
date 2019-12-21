import 'package:encrypt/encrypt.dart';

void main() {
  final key = Key.fromBase64('BwwfHxgKDwcXAxkWDwEHDBseIREPIA4QDxYOEBIDIRY=');
  final iv = IV.fromBase64('FxIOBAcEEhISHgICCRYhEA==');
  final encrypter = Encrypter(AES(key, mode: AESMode.cbc));
  final encrypted = encrypter.encrypt('hello world', iv: iv);

  print(encrypted.base64); // 857LfvASUhUMtwG6M5CHIQ==
  print(encrypted.base16); // f39ecb7ef01252150cb701ba33908721
  print(encrypted.bytes.length); // 16
}
