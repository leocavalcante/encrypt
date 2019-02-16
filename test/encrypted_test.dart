import 'dart:typed_data';

import 'package:encrypt/encrypt.dart';
import 'package:test/test.dart';

void main() {
  group('Encrypted', () {
    test('Encrypted', () {
      final encrypted = Encrypted(Uint8List(3));
      expect(encrypted.bytes, equals([0, 0, 0]));
    });

    test('fromBase16', () {
      final encrypted = Encrypted.fromBase16('000102');
      expect(encrypted.bytes, equals([0, 1, 2]));
    });

    test('fromBase64', () {
      final encrypted = Encrypted.fromBase64('AAEC');
      expect(encrypted.bytes, equals([0, 1, 2]));
    });

    test('fromLength', () {
      final encrypted = Encrypted.fromLength(3);
      expect(encrypted.bytes, equals([0, 0, 0]));
    });

    test('fromUtf8', () {
      final encrypted = Encrypted.fromUtf8('\u0000\u0001\u0002');
      expect(encrypted.bytes, equals([0, 1, 2]));
    });
  });
}
