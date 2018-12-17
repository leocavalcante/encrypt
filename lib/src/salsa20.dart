import '../encrypt.dart';

import 'package:pointycastle/stream/salsa20.dart';

import 'package:pointycastle/api.dart' show ParametersWithIV, KeyParameter;

import 'dart:typed_data';

import 'helpers.dart';

/// Wraps the Salsa20 Engine.
class Salsa20 implements Algorithm {
  final String key;
  final String iv;
  final ParametersWithIV<KeyParameter> _params;

  final Salsa20Engine _cipher = Salsa20Engine();

  Salsa20(this.key, this.iv)
      : _params = ParametersWithIV<KeyParameter>(
            KeyParameter(Uint8List.fromList(key.codeUnits)),
            Uint8List.fromList(iv.codeUnits));

  @override
  String encrypt(String plainText) {
    _cipher
      ..reset()
      ..init(true, _params);

    final input = Uint8List.fromList(plainText.codeUnits);
    final output = _cipher.process(input);

    return formatBytesAsHexString(output);
  }

  @override
  String decrypt(String cipherText) {
    _cipher
      ..reset()
      ..init(false, _params);

    final input = createUint8ListFromHexString(cipherText);
    final output = _cipher.process(input);

    return String.fromCharCodes(output);
  }
}
