// ignore_for_file: file_names

import 'package:args/args.dart';
import 'package:encrypt/encrypt.dart';

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

  final secureRandom = SecureRandom(length);

  switch (base) {
    case 64:
      print(secureRandom.base64);
      break;

    case 16:
      print(secureRandom.base16);
      break;

    default:
      print('Base $base not handled');
  }
}
