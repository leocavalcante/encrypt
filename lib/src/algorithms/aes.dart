part of encrypt;

/// Wraps the AES Algorithm.
class AES implements Algorithm {
  final Key key;
  final AESMode mode;
  final String? padding;
  final BlockCipher _cipher;
  final StreamCipher? _streamCipher;

  AES(this.key, {this.mode = AESMode.sic, this.padding = 'PKCS7'})
      : _cipher = padding != null
            ? PaddedBlockCipher('AES/${_modes[mode]}/$padding')
            : BlockCipher('AES/${_modes[mode]}'),
        _streamCipher = padding == null && _streamable.contains(mode)
            ? StreamCipher('AES/${_modes[mode]}')
            : null;

  @override
  Encrypted encrypt(Uint8List bytes, {IV? iv}) {
    if (iv == null) {
      throw StateError('IV is required.');
    }

    if (_streamCipher != null) {
      _streamCipher!
        ..reset()
        ..init(true, _buildParams(iv));

      return Encrypted(_streamCipher!.process(bytes));
    }

    _cipher
      ..reset()
      ..init(true, _buildParams(iv));

    if (padding != null) {
      return Encrypted(_cipher.process(bytes));
    }

    return Encrypted(_processBlocks(bytes));
  }

  @override
  Uint8List decrypt(Encrypted encrypted, {IV? iv}) {
    if (iv == null) {
      throw StateError('IV is required.');
    }

    if (_streamCipher != null) {
      _streamCipher!
        ..reset()
        ..init(false, _buildParams(iv));

      return _streamCipher!.process(encrypted.bytes);
    }

    _cipher
      ..reset()
      ..init(false, _buildParams(iv));

    if (padding != null) {
      return _cipher.process(encrypted.bytes);
    }

    return _processBlocks(encrypted.bytes);
  }

  Uint8List _processBlocks(Uint8List input) {
    var output = Uint8List(input.lengthInBytes);

    for (int offset = 0; offset < input.lengthInBytes;) {
      offset += _cipher.processBlock(input, offset, output, offset);
    }

    return output;
  }

  CipherParameters _buildParams(IV iv) {
    if (padding != null) {
      return _paddedParams(iv);
    }

    if (mode == AESMode.ecb) {
      return KeyParameter(key.bytes);
    }

    return ParametersWithIV<KeyParameter>(KeyParameter(key.bytes), iv.bytes);
  }

  PaddedBlockCipherParameters _paddedParams(IV iv) {
    if (mode == AESMode.ecb) {
      return PaddedBlockCipherParameters(KeyParameter(key.bytes), null);
    }

    return PaddedBlockCipherParameters(
        ParametersWithIV<KeyParameter>(KeyParameter(key.bytes), iv.bytes),
        null);
  }
}

enum AESMode {
  cbc,
  cfb64,
  ctr,
  ecb,
  ofb64Gctr,
  ofb64,
  sic,
}

const Map<AESMode, String> _modes = {
  AESMode.cbc: 'CBC',
  AESMode.cfb64: 'CFB-64',
  AESMode.ctr: 'CTR',
  AESMode.ecb: 'ECB',
  AESMode.ofb64Gctr: 'OFB-64/GCTR',
  AESMode.ofb64: 'OFB-64',
  AESMode.sic: 'SIC',
};

const List<AESMode> _streamable = [
  AESMode.sic,
  AESMode.ctr,
];
