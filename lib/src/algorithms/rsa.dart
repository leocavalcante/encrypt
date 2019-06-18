part of encrypt;

/// Wraps the RSA Engine Algorithm.
class RSA extends Algorithm {
  final RSAPublicKey publicKey;
  final RSAPrivateKey privateKey;
  final bool isSignature;

  final PublicKeyParameter<RSAPublicKey> _publicKeyParams;
  final PrivateKeyParameter<RSAPrivateKey> _privateKeyParams;

  final AsymmetricBlockCipher _cipher = PKCS1Encoding(RSAEngine());

  RSA({this.publicKey, this.privateKey, this.isSignature = false})
      : this._publicKeyParams = PublicKeyParameter(publicKey),
        this._privateKeyParams = PrivateKeyParameter(privateKey);

  @override
  Encrypted encrypt(Uint8List bytes, {IV iv}) {
    if (!isSignature && publicKey == null) {
      throw StateError('Can\'t encrypt without a public key, null given.');
    }

    _cipher
      ..reset()
      ..init(true, isSignature ? _privateKeyParams : _publicKeyParams);

    return Encrypted(_cipher.process(bytes));
  }

  @override
  Uint8List decrypt(Encrypted encrypted, {IV iv}) {
    if (!isSignature && privateKey == null) {
      throw StateError('Can\'t decrypt without a private key, null given.');
    }

    _cipher
      ..reset()
      ..init(false, isSignature ? _publicKeyParams : _privateKeyParams);

    return _cipher.process(encrypted.bytes);
  }
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

    return RSAPublicKey(modulus, exponent);
  }

  RSAAsymmetricKey _parsePrivate(ASN1Sequence sequence) {
    final modulus = (sequence.elements[1] as ASN1Integer).valueAsBigInteger;
    final exponent = (sequence.elements[3] as ASN1Integer).valueAsBigInteger;
    final p = (sequence.elements[4] as ASN1Integer).valueAsBigInteger;
    final q = (sequence.elements[5] as ASN1Integer).valueAsBigInteger;

    return RSAPrivateKey(modulus, exponent, p, q);
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
