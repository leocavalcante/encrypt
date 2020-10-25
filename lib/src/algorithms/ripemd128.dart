part of encrypt;

// ref: https://github.com/zhansliu/writemdict/blob/master/ripemd128.py

int f(int j, int x, int y, int z) {
  if (j < 16) {
    return x ^ y ^ z;
  } else if (j < 32) {
    return (x & y) | (z & ~x);
  } else if (j < 48) {
    return (x | (0xffffffff & ~y)) ^ z;
  } else {
    return (x & z) | (y & ~z);
  }
}

int K(int j) {
  if (j < 16) {
    return 0x00000000;
  } else if (j < 32) {
    return 0x5a827999;
  } else if (j < 48) {
    return 0x6ed9eba1;
  } else {
    return 0x8f1bbcdc;
  }
}

int Kp(int j) {
  if (j < 16) {
    return 0x50a28be6;
  } else if (j < 32) {
    return 0x5c4dd124;
  } else if (j < 48) {
    return 0x6d703ef3;
  } else {
    return 0x00000000;
  }
}

int add([List<int> args]) {
  int sum = 0;
  for (int i = 0; i < args.length; i++) {
    sum += args[i];
  }
  return sum & 0xffffffff;
}

int rol(int s, int x) {
  return (x << s | x >> (32 - s)) & 0xffffffff;
}

const r = [
  // ignore:
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
  3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
  1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2
];
const rp = [
  // ignore:
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
  6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
  15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
  8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14
];
const s = [
  // ignore:
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
  7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
  11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
  11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12
];
const sp = [
  // ignore:
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
  9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
  9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
  15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8
];

List<List<int>> padandsplit(Uint8List message) {
  var origlen = message.length;
  var padlength = 64 - ((origlen - 56) % 64); //minimum padding is 1!

  var list = List<int>();

  list.addAll(message);

  list.add(0x80);

  list.addAll(ByteData(padlength - 1).buffer.asUint8List());

  var origlenBuffer = ByteData(8);
  origlenBuffer.setUint64(0, origlen * 8, Endian.little);
  list.addAll(origlenBuffer.buffer.asUint8List());

  Uint8List padList = Uint8List.fromList(list);
  int blockCount = padList.length ~/ 64;
  int intCount = 64;
  List<List<int>> X = List<List<int>>();
  for (int i = 0; i < blockCount; i += 64) {
    List<int> row = List<int>();
    for (int j = 0; j < intCount; j += 4) {
      row.add(ByteData.sublistView(padList, i + j, i + j + 4)
          .getUint32(0, Endian.little));
    }
    X.add(row);
  }
  return X;
}

class Ripemd128 implements Algorithm {
  Ripemd128() {}

  @override
  Encrypted encrypt(Uint8List bytes, {IV iv}) {
    List<List<int>> X = padandsplit(bytes);

    var h0 = 0x67452301;
    var h1 = 0xefcdab89;
    var h2 = 0x98badcfe;
    var h3 = 0x10325476;

    for (var i = 0; i < X.length; i++) {
      var A = h0;
      var B = h1;
      var C = h2;
      var D = h3;

      var Ap = h0;
      var Bp = h1;
      var Cp = h2;
      var Dp = h3;
      var T = 0;
      for (var j = 0; j < 64; j++) {
        T = rol(s[j], add([A, f(j, B, C, D), X[i][r[j]], K(j)]));
        A = D;
        D = C;
        C = B;
        B = T;
        T = rol(sp[j], add([Ap, f(63 - j, Bp, Cp, Dp), X[i][rp[j]], Kp(j)]));
        Ap = Dp;
        Dp = Cp;
        Cp = Bp;
        Bp = T;
      }
      T = add([h1, C, Dp]);
      h1 = add([h2, D, Ap]);
      h2 = add([h3, A, Bp]);
      h3 = add([h0, B, Cp]);
      h0 = T;
    }

    ByteData result = ByteData(16);
    result.setUint32(0, h0, Endian.little);
    result.setUint32(4, h1, Endian.little);
    result.setUint32(8, h2, Endian.little);
    result.setUint32(12, h3, Endian.little);
    return Encrypted(result.buffer.asUint8List());
  }

  @override
  Uint8List decrypt(Encrypted encrypted, {IV iv}) {
    return null;
  }
}
