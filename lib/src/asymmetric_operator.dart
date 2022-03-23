part of '../crypto_keys.dart';

abstract class _AsymmetricOperator<T extends Key> implements Operator<T> {
  static pc.ECDomainParameters createCurveParameters(Identifier curve) {
    var name = curve.name.split('/').last;
    switch (name) {
      case 'P-256':
        return pc.ECCurve_secp256r1();
      case 'P-256K':
        return pc.ECCurve_secp256k1();
      case 'P-384':
        return pc.ECCurve_secp384r1();
      case 'P-521':
        return pc.ECCurve_secp521r1();
      case 'BP-256r1':
        return pc.ECCurve_brainpoolp256r1();
    }
    throw ArgumentError('Unknwon curve type $name');
  }

  pc.ECDomainParameters get ecDomainParameters =>
      createCurveParameters((key as EcKey).curve);

  pc.AsymmetricKeyParameter get keyParameter {
    if (key is RsaPrivateKey) {
      var k = key as RsaPrivateKey;
      return pc.PrivateKeyParameter<pc.RSAPrivateKey>(pc.RSAPrivateKey(
          k.modulus,
          k.privateExponent,
          k.firstPrimeFactor,
          k.secondPrimeFactor));
    }
    if (key is RsaPublicKey) {
      var k = key as RsaPublicKey;
      return pc.PublicKeyParameter<pc.RSAPublicKey>(pc.RSAPublicKey(
        k.modulus,
        k.exponent,
      ));
    }
    var d = ecDomainParameters;

    if (key is EcPrivateKey) {
      var k = key as EcPrivateKey;
      return pc.PrivateKeyParameter<pc.ECPrivateKey>(pc.ECPrivateKey(
        k.eccPrivateKey,
        d,
      ));
    }
    if (key is EcPublicKey) {
      var k = key as EcPublicKey;

      return pc.PublicKeyParameter<pc.ECPublicKey>(
          pc.ECPublicKey(d.curve.createPoint(k.xCoordinate, k.yCoordinate), d));
    }
    throw StateError('Unexpected key type $key');
  }
}

class _AsymmetricSigner extends Signer<PrivateKey>
    with _AsymmetricOperator<PrivateKey> {
  _AsymmetricSigner(Identifier algorithm, PrivateKey key)
      : super._(algorithm, key);

  @override
  pc.Signer get _algorithm => super._algorithm as pc.Signer;

  @override
  Signature sign(List<int> data) {
    data = data is Uint8List ? data : Uint8List.fromList(data);
    _algorithm.init(
        true, pc.ParametersWithRandom(keyParameter, DefaultSecureRandom()));

    if (key is RsaKey) {
      return Signature(
          (_algorithm.generateSignature(data) as pc.RSASignature).bytes);
    }
    if (key is EcKey) {
      var sig = _algorithm.generateSignature(data) as pc.ECSignature;

      var length = {
        curves.p256: 32,
        curves.p256k: 32,
        curves.p384: 48,
        curves.p521: 66,
        curves.bp256r1: 32,
      }[(key as EcKey).curve]!;
      var bytes = Uint8List(length * 2);
      bytes.setRange(
          0, length, _bigIntToBytes(sig.r, length).toList().reversed);
      bytes.setRange(
          length, length * 2, _bigIntToBytes(sig.s, length).toList().reversed);

      return Signature(bytes);
    }
    throw UnsupportedError('Unknown key type $key');
  }
}

class _AsymmetricVerifier extends Verifier<PublicKey>
    with _AsymmetricOperator<PublicKey> {
  _AsymmetricVerifier(Identifier algorithm, PublicKey key)
      : super._(algorithm, key);

  @override
  pc.Signer get _algorithm => super._algorithm as pc.Signer;

  @override
  bool verify(Uint8List data, Signature signature) {
    if (key is RsaKey) {
      _algorithm.init(false,
          pc.ParametersWithRandom(keyParameter, pc.SecureRandom('Fortuna')));
      try {
        return _algorithm.verifySignature(
            data, pc.RSASignature(signature.data));
      } on ArgumentError {
        return false;
      }
    }
    if (key is EcKey) {
      _algorithm.init(false, keyParameter);

      var l = signature.data.length ~/ 2;

      return _algorithm.verifySignature(
          data,
          pc.ECSignature(
            _bigIntFromBytes(signature.data.take(l)),
            _bigIntFromBytes(signature.data.skip(l)),
          ));
    }
    throw UnsupportedError('Unknown key type $key');
  }
}

class _AsymmetricEncrypter extends Encrypter<Key> with _AsymmetricOperator {
  _AsymmetricEncrypter(Identifier algorithm, Key key) : super._(algorithm, key);

  @override
  pc.AsymmetricBlockCipher get _algorithm =>
      super._algorithm as pc.AsymmetricBlockCipher;

  @override
  Uint8List decrypt(EncryptionResult input) {
    _algorithm.init(
        false,
        pc.ParametersWithRandom(keyParameter, pc.SecureRandom('Fortuna')
            // ..seed(pc.KeyParameter(Uint8List(32)))
            ));

    return _algorithm.process(input.data);
  }

  @override
  EncryptionResult encrypt(List<int> input,
      {Uint8List? initializationVector,
      Uint8List? additionalAuthenticatedData}) {
    _algorithm.init(
        true, pc.ParametersWithRandom(keyParameter, DefaultSecureRandom()));

    return EncryptionResult(_algorithm.process(input as Uint8List));
  }
}

final _b256 = BigInt.from(256);

Iterable<int> _bigIntToBytes(BigInt v, int length) sync* {
  for (var i = 0; i < length; i++) {
    yield (v % _b256).toInt();
    v = v ~/ _b256;
  }
}

BigInt _bigIntFromBytes(Iterable<int> bytes) {
  return bytes.fold(BigInt.zero, (a, b) => a * _b256 + BigInt.from(b));
}

class _KeyDerivator extends Encrypter<Key> with _AsymmetricOperator {
  _KeyDerivator(Identifier algorithm, Key key) : super._(algorithm, key);

  late final pc.ECDHKDFParameters _parameters;
  late final int _keyBitLength;
  late final Uint8List _otherInfo;

  @override
  pc.KeyDerivator get _algorithm => super._algorithm as pc.KeyDerivator;

  void init(EcPublicKey epk, int keyBitLength,Uint8List otherInfo) {
    final d = _AsymmetricOperator.createCurveParameters(epk.curve);
    final pcepk = pc.ECPublicKey(
        d.curve.createPoint(epk.xCoordinate, epk.yCoordinate), d);
    _parameters =
        pc.ECDHKDFParameters(keyParameter.key as pc.ECPrivateKey, pcepk);
    _keyBitLength = keyBitLength;
    _otherInfo = otherInfo;
  }



  @override
  Uint8List decrypt(EncryptionResult input) {
    if (input.data.isEmpty) {
      // ECDH-ES
      var ecdh = _algorithm..init(_parameters);
      var z = ecdh.process(Uint8List(0));
      var c = pc.HkdfParameters(z, _keyBitLength, _otherInfo);
      var concatKdf = pc.KeyDerivator('SHA-256/ConcatKDF')..init(c);
      return concatKdf.process(Uint8List(0));
    }
    // TODO: implement decrypt for other ECDH variants
    throw UnimplementedError();
  }

  @override
  EncryptionResult encrypt(Uint8List input,
      {Uint8List? initializationVector,
      Uint8List? additionalAuthenticatedData}) {
    // TODO: implement encrypt
    throw UnimplementedError();
  }
}
