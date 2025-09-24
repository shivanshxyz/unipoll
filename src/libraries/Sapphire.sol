// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

library Sapphire {
    address internal constant RANDOM_BYTES = 0x0100000000000000000000000000000000000001;
    address internal constant DERIVE_KEY = 0x0100000000000000000000000000000000000002;
    address internal constant ENCRYPT = 0x0100000000000000000000000000000000000003;
    address internal constant DECRYPT = 0x0100000000000000000000000000000000000004;
    address internal constant GENERATE_SIGNING_KEYPAIR = 0x0100000000000000000000000000000000000005;
    address internal constant SIGN_DIGEST = 0x0100000000000000000000000000000000000006;
    address internal constant VERIFY_DIGEST = 0x0100000000000000000000000000000000000007;
    address internal constant CURVE25519_PUBLIC_KEY = 0x0100000000000000000000000000000000000008;
    address internal constant GAS_USED = 0x0100000000000000000000000000000000000009;
    address internal constant PAD_GAS = 0x010000000000000000000000000000000000000a;

    address internal constant SHA512_256 = 0x0100000000000000000000000000000000000101;
    address internal constant SHA512 = 0x0100000000000000000000000000000000000102;
    address internal constant SHA384 = 0x0100000000000000000000000000000000000104;

    type Curve25519PublicKey is bytes32;
    type Curve25519SecretKey is bytes32;

    enum SigningAlg {
        Ed25519Oasis,
        Ed25519Pure,
        Ed25519PrehashedSha512,
        Secp256k1Oasis,
        Secp256k1PrehashedKeccak256,
        Secp256k1PrehashedSha256,
        Sr25519,
        Secp256r1PrehashedSha256,
        Secp384r1PrehashedSha384
    }

    function randomBytes(uint256 numBytes, bytes memory pers) internal view returns (bytes memory) {
        (bool success, bytes memory entropy) = RANDOM_BYTES.staticcall(abi.encode(numBytes, pers));
        require(success, "randomBytes: failed");
        return entropy;
    }

    function generateCurve25519KeyPair(bytes memory pers)
        internal
        view
        returns (Curve25519PublicKey pk, Curve25519SecretKey sk)
    {
        bytes memory scalar = randomBytes(32, pers);
        scalar[0] &= 0xf8;
        scalar[31] &= 0x7f;
        scalar[31] |= 0x40;
        (bool success, bytes memory pkBytes) = CURVE25519_PUBLIC_KEY.staticcall(scalar);
        require(success, "gen curve25519 pk: failed");
        return (Curve25519PublicKey.wrap(bytes32(pkBytes)), Curve25519SecretKey.wrap(bytes32(scalar)));
    }

    function deriveSymmetricKey(Curve25519PublicKey peerPublicKey, Curve25519SecretKey secretKey)
        internal
        view
        returns (bytes32)
    {
        (bool success, bytes memory symmetric) = DERIVE_KEY.staticcall(abi.encode(peerPublicKey, secretKey));
        require(success, "deriveSymmetricKey: failed");
        return bytes32(symmetric);
    }

    function encrypt(bytes32 key, bytes32 nonce, bytes memory plaintext, bytes memory additionalData)
        internal
        view
        returns (bytes memory)
    {
        (bool success, bytes memory ciphertext) = ENCRYPT.staticcall(abi.encode(key, nonce, plaintext, additionalData));
        require(success, "encrypt: failed");
        return ciphertext;
    }

    function decrypt(bytes32 key, bytes32 nonce, bytes memory ciphertext, bytes memory additionalData)
        internal
        view
        returns (bytes memory)
    {
        (bool success, bytes memory plaintext) = DECRYPT.staticcall(abi.encode(key, nonce, ciphertext, additionalData));
        require(success, "decrypt: failed");
        return plaintext;
    }

    function generateSigningKeyPair(SigningAlg alg, bytes memory seed)
        internal
        view
        returns (bytes memory publicKey, bytes memory secretKey)
    {
        (bool success, bytes memory keypair) = GENERATE_SIGNING_KEYPAIR.staticcall(abi.encode(alg, seed));
        require(success, "gen signing keypair: failed");
        return abi.decode(keypair, (bytes, bytes));
    }

    function sign(SigningAlg alg, bytes memory secretKey, bytes memory contextOrHash, bytes memory message)
        internal
        view
        returns (bytes memory signature)
    {
        (bool success, bytes memory sig) = SIGN_DIGEST.staticcall(abi.encode(alg, secretKey, contextOrHash, message));
        require(success, "sign: failed");
        return sig;
    }

    function verify(
        SigningAlg alg,
        bytes memory publicKey,
        bytes memory contextOrHash,
        bytes memory message,
        bytes memory signature
    ) internal view returns (bool verified) {
        (bool success, bytes memory v) = VERIFY_DIGEST.staticcall(abi.encode(alg, publicKey, contextOrHash, message, signature));
        require(success, "verify: failed");
        return abi.decode(v, (bool));
    }

    function padGas(uint128 toAmount) internal view {
        (bool success,) = PAD_GAS.staticcall(abi.encode(toAmount));
        require(success, "verify: failed");
    }

    function gasUsed() internal view returns (uint64) {
        (bool success, bytes memory v) = GAS_USED.staticcall("");
        require(success, "gasused: failed");
        return abi.decode(v, (uint64));
    }
}

function sha512_256(bytes memory input) view returns (bytes32 result) {
    (bool success, bytes memory output) = Sapphire.SHA512_256.staticcall(input);
    require(success, "sha512_256");
    return bytes32(output);
}

function sha512(bytes memory input) view returns (bytes memory output) {
    bool success;
    (success, output) = Sapphire.SHA512.staticcall(input);
    require(success, "sha512");
}

function sha384(bytes memory input) view returns (bytes memory output) {
    bool success;
    (success, output) = Sapphire.SHA384.staticcall(input);
    require(success, "sha384");
}
