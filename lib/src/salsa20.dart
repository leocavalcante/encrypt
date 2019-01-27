import 'dart:typed_data';

import 'package:pointycastle/api.dart' show ParametersWithIV, KeyParameter;
import 'package:pointycastle/stream/salsa20.dart';

import '../encrypt.dart';

/// Wraps the Salsa20 Engine.
class Salsa20 implements Algorithm {
  final String key;
  final IV iv;
  final ParametersWithIV<KeyParameter> _params;

  final Salsa20Engine _cipher = Salsa20Engine();

  Salsa20(this.key, this.iv)
      : _params = ParametersWithIV<KeyParameter>(
            KeyParameter(Uint8List.fromList(key.codeUnits)), iv.bytes);

  @override
  Encrypted encrypt(Uint8List bytes) {
    _cipher
      ..reset()
      ..init(true, _params);

    return Encrypted(_cipher.process(bytes));
  }

  @override
  Uint8List decrypt(Encrypted encrypted) {
    _cipher
      ..reset()
      ..init(false, _params);

    return _cipher.process(encrypted.bytes);
  }
}
