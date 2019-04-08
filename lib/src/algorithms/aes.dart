part of encrypt;

/// Wraps the AES Algorithm.
class AES implements Algorithm {
  final Key key;
  final IV iv;
  final AESMode mode;
  final String padding;
  final CipherParameters _params;
  final BlockCipher _cipher;

  AES(this.key, this.iv, {this.mode = AESMode.sic, this.padding = 'PKCS7'})
      : _cipher = padding != null
            ? PaddedBlockCipher('AES/${_modes[mode]}/$padding')
            : BlockCipher('AES/${_modes[mode]}'),
        _params = padding == null
            ? (mode == AESMode.ecb
                ? KeyParameter(key.bytes)
                : ParametersWithIV<KeyParameter>(
                    KeyParameter(key.bytes), iv.bytes))
            : PaddedBlockCipherParameters(
                mode == AESMode.ecb
                    ? KeyParameter(key.bytes)
                    : ParametersWithIV<KeyParameter>(
                        KeyParameter(key.bytes), iv.bytes),
                null,
              );

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
