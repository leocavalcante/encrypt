import 'dart:convert';
import 'dart:math';

import 'package:args/args.dart';

void main(List<String> args) {
  final argParser = ArgParser();

  argParser.addOption('length',
      abbr: 'l', defaultsTo: '32', help: 'The length of the bytes');

  argParser.addOption('base',
      abbr: 'b',
      defaultsTo: '64',
      help: 'Bytes represented as base 64 or base 16 (Hexdecimal)');

  argParser.addFlag('help',
      abbr: 'h', defaultsTo: false, help: 'Show this help message');

  final results = argParser.parse(args);

  final length = int.parse(results['length'].toString());
  final base = int.parse(results['base'].toString());
  final help = results['help'] as bool;

  if (help) {
    return print(argParser.usage);
  }

  final random = Random.secure();
  final bytes = List.generate(length, (i) => random.nextInt(2 ^ 32));

  switch (base) {
    case 64:
      print(base64.encode(bytes));
      break;

    case 16:
      print(bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join());
      break;

    default:
      print('Base $base not handled');
  }
}
