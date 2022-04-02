import 'dart:typed_data';

import 'package:crypto_keys/crypto_keys.dart';

void main() async {
  // Create a key pair from a JWK representation
  var keyPair = KeyPair.fromJwk({
    'kty': 'oct',
    'k': 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75'
        'aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow'
  });

  // A key pair has a private and public key, possibly one of them is null, if
  // required info was not available when construction
  // The private key can be used for signing
  var privateKey = keyPair.privateKey!;

  // Create a signer for the key using the HMAC/SHA-256 algorithm
  var signer = privateKey.createSigner(algorithms.signing.hmac.sha256);

  // Sign some content, to be integrity protected
  var content = "It's me, really me";
  var signature = await signer.sign("It's me, really me".codeUnits);

  print("Signing '$content'");
  print('Signature: ${signature.data}');

  // The public key can be used for verifying the signature
  var publicKey = keyPair.publicKey!;

  // Create a verifier for the key using the specified algorithm
  var verifier = publicKey.createVerifier(algorithms.signing.hmac.sha256);

  var verified =
      await verifier.verify(Uint8List.fromList(content.codeUnits), signature);
  if (verified) {
    print('Verification succeeded');
  } else {
    print('Verification failed');
  }
}
