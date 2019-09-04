import 'dart:io';

import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/asymmetric/api.dart';

Future<T> parseKeyFromFile<T extends RSAAsymmetricKey>(String filename) async {
  final file = File(filename);
  final key = await file.readAsString();
  final parser = RSAKeyParser();
  return parser.parse(key) as T;
}
