import '../encrypt.dart';

import 'package:pointycastle/stream/salsa20.dart';

import 'package:pointycastle/api.dart' show ParametersWithIV, KeyParameter;

import 'dart:typed_data';

import 'helpers.dart';

class Salsa20 implements Algorithm {
  final String key;
  final String iv;
  final ParametersWithIV _params;

  final Salsa20Engine _cipher = new Salsa20Engine();

  Salsa20(this.key, this.iv)
      : _params = new ParametersWithIV(
            new KeyParameter(new Uint8List.fromList(key.codeUnits)),
            new Uint8List.fromList(iv.codeUnits));

  String encrypt(String plainText) {
    _cipher
      ..reset()
      ..init(true, _params);

    final input = new Uint8List.fromList(plainText.codeUnits);
    final output = _cipher.process(input);

    return formatBytesAsHexString(output);
  }

  String decrypt(String cipherText) {
    _cipher
      ..reset()
      ..init(false, _params);

    final input = createUint8ListFromHexString(cipherText);
    final output = _cipher.process(input);

    return new String.fromCharCodes(output);
  }
}
