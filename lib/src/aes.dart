import 'dart:typed_data';

import 'package:pointycastle/api.dart' hide Algorithm;

import '../encrypt.dart';

/// Wraps the AES Algorithm.
class AES implements Algorithm {
  final String key;
  final IV iv;
  final PaddedBlockCipherParameters _params;
  final PaddedBlockCipher _cipher = PaddedBlockCipher('AES/SIC/PKCS7');

  AES(this.key, this.iv)
      : _params = PaddedBlockCipherParameters(
            ParametersWithIV<KeyParameter>(
                KeyParameter(Uint8List.fromList(key.codeUnits)), iv.bytes),
            null);

  @override
  Encrypted encrypt(String text) {
    _cipher
      ..reset()
      ..init(true, _params);

    return Encrypted(_cipher.process(Uint8List.fromList(text.codeUnits)));
  }

  @override
  String decrypt(Encrypted encrypted) {
    _cipher
      ..reset()
      ..init(false, _params);

    return String.fromCharCodes(_cipher.process(encrypted.bytes));
  }
}
