import 'dart:typed_data';

import 'package:encrypt/encrypt.dart';

void main() {
  final salt = Uint8List(16);
  final key = Key.fromUtf8('short').stretch(32, salt: salt);

  print(key.base64);
}
