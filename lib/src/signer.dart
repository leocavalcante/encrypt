part of encrypt;

class Signer {
  final SignerAlgorithm algo;

  Signer(this.algo);

  Encrypted sign(String input) => signBytes(convert.utf8.encode(input));

  Encrypted signBytes(List<int> bytes) => algo.sign(Uint8List.fromList(bytes));

  bool verifyBytes(List<int> bytes, Encrypted signature) =>
      algo.verify(Uint8List.fromList(bytes), signature);

  bool verify(String input, Encrypted signature) =>
      verifyBytes(convert.utf8.encode(input), signature);

  bool verify16(String input, String signature) =>
      verify(input, Encrypted.fromBase16(signature));

  bool verify64(String input, String signature) =>
      verify(input, Encrypted.fromBase64(signature));
}
