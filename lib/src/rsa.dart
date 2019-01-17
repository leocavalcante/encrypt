import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:pointycastle/api.dart' hide Algorithm;
import 'package:pointycastle/asymmetric/api.dart';
import "package:pointycastle/asymmetric/pkcs1.dart";
import 'package:pointycastle/asymmetric/rsa.dart';

import './helpers.dart';
import '../encrypt.dart';

/// Wraps the RSA Engine Algorithm.
class RSA extends Algorithm {
  final RSAPublicKey publicKey;
  final RSAPrivateKey privateKey;

  final PublicKeyParameter<RSAPublicKey> _publicKeyParams;
  final PrivateKeyParameter<RSAPrivateKey> _privateKeyParameter;

  final AsymmetricBlockCipher _cipher = PKCS1Encoding(RSAEngine());

  RSA(this.publicKey, this.privateKey)
      : this._publicKeyParams = PublicKeyParameter(publicKey),
        this._privateKeyParameter = PrivateKeyParameter(privateKey);

  @override
  String encrypt(String plainText) {
    _cipher
      ..reset()
      ..init(true, _publicKeyParams);

    final input = Uint8List.fromList(plainText.codeUnits);
    final output = _cipher.process(input);

    return formatBytesAsHexString(output);
  }

  @override
  String decrypt(String cipherText) {
    _cipher
      ..reset()
      ..init(false, _privateKeyParameter);

    final input = createUint8ListFromHexString(cipherText);
    final output = _cipher.process(input);

    return String.fromCharCodes(output);
  }
}

/// RSA PEM parser.
class RSAKeyParser {
  /// Parses the PEM key no matter it is public or private, it will figure it out.
  RSAAsymmetricKey parse(String key) {
    final rows = key.split('\n'); // LF-only, this could be a problem
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

    // NOTE: Should we throw an exception?
    return null;
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

    final keyBytes = Uint8List.fromList(base64.decode(keyText));
    final asn1Parser = ASN1Parser(keyBytes);

    return asn1Parser.nextObject() as ASN1Sequence;
  }

  ASN1Sequence _pkcs8PublicSequence(ASN1Sequence sequence) {
    final ASN1BitString bitString = sequence.elements[1];
    final bytes = bitString.valueBytes().sublist(1);
    final parser = ASN1Parser(Uint8List.fromList(bytes));

    return parser.nextObject() as ASN1Sequence;
  }

  ASN1Sequence _pkcs8PrivateSequence(ASN1Sequence sequence) {
    final ASN1BitString bitString = sequence.elements[2];
    final bytes = bitString.valueBytes();
    final parser = ASN1Parser(bytes);

    return parser.nextObject() as ASN1Sequence;
  }
}
