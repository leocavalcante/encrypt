import 'dart:typed_data';

import 'package:pointycastle/api.dart' show KeyParameter;
import 'package:pointycastle/block/aes_fast.dart';

import '../encrypt.dart';
import 'helpers.dart';

class AES implements Algorithm {
  final String key;
  final KeyParameter _params;
  final AESFastEngine _cipher = AESFastEngine();

  AES(this.key) : _params = KeyParameter(Uint8List.fromList(key.codeUnits));

  String encrypt(String plainText) {
    _cipher
      ..reset()
      ..init(true, _params);

    final input = Uint8List.fromList(plainText.codeUnits);
    final output = _processBlocks(input);

    return formatBytesAsHexString(output);
  }

  String decrypt(String cipherText) {
    _cipher
      ..reset()
      ..init(false, _params);

    final input = createUint8ListFromHexString(cipherText);
    final output = _processBlocks(input);

    return String.fromCharCodes(output);
  }

  Uint8List _processBlocks(Uint8List input) {
    var output = Uint8List(input.lengthInBytes);

    for (int offset = 0; offset < input.lengthInBytes;) {
      offset += _cipher.processBlock(input, offset, output, offset);
    }

    return output;
  }
}
