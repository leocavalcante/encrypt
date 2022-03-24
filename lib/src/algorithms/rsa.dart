part of encrypt;

// Abstract class for encryption and signing.
abstract class AbstractRSA {
  final RSAPublicKey? publicKey;
  final RSAPrivateKey? privateKey;
  PublicKeyParameter<RSAPublicKey>? get _publicKeyParams =>
      publicKey != null ? PublicKeyParameter(publicKey!) : null;
  PrivateKeyParameter<RSAPrivateKey>? get _privateKeyParams =>
      privateKey != null ? PrivateKeyParameter(privateKey!) : null;
  final AsymmetricBlockCipher _cipher;

  AbstractRSA({
    this.publicKey,
    this.privateKey,
    RSAEncoding encoding = RSAEncoding.PKCS1,
    RSADigest digest = RSADigest.SHA1,
  }) : this._cipher = encoding == RSAEncoding.OAEP
            ? digest == RSADigest.SHA1
              ? OAEPEncoding(RSAEngine())
              : OAEPEncoding.withSHA256(RSAEngine())
            : PKCS1Encoding(RSAEngine());
}

/// Wraps the RSA Engine Algorithm.
class RSA extends AbstractRSA implements Algorithm {
  RSA(
      {RSAPublicKey? publicKey,
      RSAPrivateKey? privateKey,
      RSAEncoding encoding = RSAEncoding.PKCS1,
      RSADigest digest = RSADigest.SHA1})
      : super(
        publicKey: publicKey,
        privateKey: privateKey,
        encoding: encoding,
        digest: digest,
      );

  @override
  Encrypted encrypt(Uint8List bytes, {IV? iv, Uint8List? associatedData}) {
    if (publicKey == null) {
      throw StateError('Can\'t encrypt without a public key, null given.');
    }

    _cipher
      ..reset()
      ..init(true, _publicKeyParams!);

    return Encrypted(_cipher.process(bytes));
  }

  @override
  Uint8List decrypt(Encrypted encrypted, {IV? iv, Uint8List? associatedData}) {
    if (privateKey == null) {
      throw StateError('Can\'t decrypt without a private key, null given.');
    }

    _cipher
      ..reset()
      ..init(false, _privateKeyParams!);

    return _cipher.process(encrypted.bytes);
  }
}

class RSASigner extends AbstractRSA implements SignerAlgorithm {
  final RSASignDigest digest;
  final Uint8List _digestId;
  final Digest _digestCipher;

  RSASigner(this.digest, {RSAPublicKey? publicKey, RSAPrivateKey? privateKey})
      : _digestId = _digestIdFactoryMap[digest]!.id,
        _digestCipher = _digestIdFactoryMap[digest]!.factory(),
        super(publicKey: publicKey, privateKey: privateKey);

  @override
  Encrypted sign(Uint8List bytes) {
    if (privateKey == null) {
      throw StateError('Can\'t sign without a private key, null given.');
    }

    final hash = Uint8List(_digestCipher.digestSize);

    _digestCipher
      ..reset()
      ..update(bytes, 0, bytes.length)
      ..doFinal(hash, 0);

    _cipher
      ..reset()
      ..init(true, _privateKeyParams!);

    return Encrypted(_cipher.process(_encode(hash)));
  }

  @override
  bool verify(Uint8List bytes, Encrypted signature) {
    if (publicKey == null) {
      throw StateError('Can\'t verify without a public key, null given.');
    }

    final hash = Uint8List(_digestCipher.digestSize);

    _digestCipher
      ..reset()
      ..update(bytes, 0, bytes.length)
      ..doFinal(hash, 0);

    _cipher
      ..reset()
      ..init(false, _publicKeyParams!);

    var _signature = Uint8List(_cipher.outputBlockSize);

    try {
      final length = _cipher.processBlock(
          signature.bytes, 0, signature.bytes.length, _signature, 0);
      _signature = _signature.sublist(0, length);
    } on ArgumentError {
      return false;
    }

    final expected = _encode(hash);

    if (_signature.length == expected.length) {
      for (var i = 0; i < _signature.length; i++) {
        if (_signature[i] != expected[i]) {
          return false;
        }
      }

      return true;
    } else if (_signature.length == expected.length - 2) {
      var sigOffset = _signature.length - hash.length - 2;
      var expectedOffset = expected.length - hash.length - 2;

      expected[1] -= 2;
      expected[3] -= 2;

      var nonEqual = 0;

      for (var i = 0; i < hash.length; i++) {
        nonEqual |= (_signature[sigOffset + i] ^ expected[expectedOffset + i]);
      }

      for (int i = 0; i < sigOffset; i++) {
        nonEqual |= (_signature[i] ^ expected[i]);
      }

      return nonEqual == 0;
    } else {
      return false;
    }
  }

  Uint8List _encode(Uint8List hash) {
    final digestBytes =
        Uint8List(2 + 2 + _digestId.length + 2 + 2 + hash.length);
    var i = 0;

    digestBytes[i++] = 48;
    digestBytes[i++] = digestBytes.length - 2;
    digestBytes[i++] = 48;
    digestBytes[i++] = _digestId.length + 2;

    digestBytes.setAll(i, _digestId);
    i += _digestId.length;

    digestBytes[i++] = 5;
    digestBytes[i++] = 0;
    digestBytes[i++] = 4;
    digestBytes[i++] = hash.length;

    digestBytes.setAll(i, hash);

    return digestBytes;
  }
}

enum RSAEncoding {
  PKCS1,
  OAEP,
}

enum RSADigest {
  SHA1,
  SHA256,
}

enum RSASignDigest {
  SHA256,
}

final _digestIdFactoryMap = <RSASignDigest, _DigestIdFactory>{
  RSASignDigest.SHA256: _DigestIdFactory(
      decodeHexString('0609608648016503040201'), () => SHA256Digest())
};

class _DigestIdFactory {
  final Uint8List id;
  final Digest Function() factory;

  _DigestIdFactory(this.id, this.factory);
}

/// RSA PEM parser.
class RSAKeyParser {
  /// Parses the PEM key no matter it is public or private, it will figure it out.
  RSAAsymmetricKey parse(String key) {
    final rows = key.split(RegExp(r'\r\n?|\n'));
    final header = rows.first;

    if (header == '-----BEGIN RSA PUBLIC KEY-----') {
      return _parsePublic(_parseSequence(rows));
    }

    if (header == '-----BEGIN PUBLIC KEY-----') {
      return _parsePublic(_pkcs8PublicSequence(_parseSequence(rows)));
    }

    if (header == '-----BEGIN RSA PRIVATE KEY-----') {
      return _parsePrivate(_parseSequence(rows));
    }

    if (header == '-----BEGIN PRIVATE KEY-----') {
      return _parsePrivate(_pkcs8PrivateSequence(_parseSequence(rows)));
    }

    throw FormatException('Unable to parse key, invalid format.', header);
  }

  RSAAsymmetricKey _parsePublic(ASN1Sequence sequence) {
    final modulus = (sequence.elements[0] as ASN1Integer).valueAsBigInteger;
    final exponent = (sequence.elements[1] as ASN1Integer).valueAsBigInteger;

    return RSAPublicKey(modulus!, exponent!);
  }

  RSAAsymmetricKey _parsePrivate(ASN1Sequence sequence) {
    final modulus = (sequence.elements[1] as ASN1Integer).valueAsBigInteger;
    final exponent = (sequence.elements[3] as ASN1Integer).valueAsBigInteger;
    final p = (sequence.elements[4] as ASN1Integer).valueAsBigInteger;
    final q = (sequence.elements[5] as ASN1Integer).valueAsBigInteger;

    return RSAPrivateKey(modulus!, exponent!, p, q);
  }

  ASN1Sequence _parseSequence(List<String> rows) {
    final keyText = rows
        .skipWhile((row) => row.startsWith('-----BEGIN'))
        .takeWhile((row) => !row.startsWith('-----END'))
        .map((row) => row.trim())
        .join('');

    final keyBytes = Uint8List.fromList(convert.base64.decode(keyText));
    final asn1Parser = ASN1Parser(keyBytes);

    return asn1Parser.nextObject() as ASN1Sequence;
  }

  ASN1Sequence _pkcs8PublicSequence(ASN1Sequence sequence) {
    final ASN1Object bitString = sequence.elements[1];
    final bytes = bitString.valueBytes().sublist(1);
    final parser = ASN1Parser(Uint8List.fromList(bytes));

    return parser.nextObject() as ASN1Sequence;
  }

  ASN1Sequence _pkcs8PrivateSequence(ASN1Sequence sequence) {
    final ASN1Object bitString = sequence.elements[2];
    final bytes = bitString.valueBytes();
    final parser = ASN1Parser(bytes);

    return parser.nextObject() as ASN1Sequence;
  }
}
