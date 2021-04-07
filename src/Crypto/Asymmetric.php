<?php

declare(strict_types=1);

namespace CQ\Crypto;

use ParagonIE\Halite\Asymmetric\Crypto;
use ParagonIE\Halite\Asymmetric\EncryptionPublicKey;
use ParagonIE\Halite\Asymmetric\EncryptionSecretKey;
use ParagonIE\Halite\Asymmetric\SignaturePublicKey;
use ParagonIE\Halite\Asymmetric\SignatureSecretKey;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\HiddenString\HiddenString;
use CQ\Crypto\Models\Keypair;

class Asymmetric
{
    public function __construct(
        private Keypair $keypair
    ) {
    }

    /**
     * Generate encryption keypair
     */
    public static function genKey(): Keypair
    {
        $keypair = new Keypair();

        $keypair->setAuthentication(
            authentication: KeyFactory::generateSignatureKeyPair()
        );
        $keypair->setEncryption(
            encryption: KeyFactory::generateEncryptionKeyPair()
        );

        return $keypair;
    }

    /**
     * Encrypt string
     */
    public static function encrypt(
        string $string,
        EncryptionPublicKey $recieverEncryptionPublicKey,
        ?EncryptionSecretKey $senderEncryptionSecretKey = null
    ): string {
        if ($senderEncryptionSecretKey) {
            return Crypto::encrypt(
                plaintext: new HiddenString($string),
                ourPrivateKey: $senderEncryptionSecretKey,
                theirPublicKey: $recieverEncryptionPublicKey
            );
        }

        return Crypto::seal(
            plaintext: new HiddenString(value: $string),
            publicKey: $recieverEncryptionPublicKey
        );
    }

    /**
     * Decrypt string
     */
    public static function decrypt(
        string $encryptedString,
        EncryptionSecretKey $recieverEncryptionPrivateKey,
        ?EncryptionPublicKey $senderEncryptionPublicKey = null
    ): string {
        if ($senderEncryptionPublicKey) {
            return Crypto::decrypt(
                ciphertext: $encryptedString,
                ourPrivateKey: $recieverEncryptionPrivateKey,
                theirPublicKey: $senderEncryptionPublicKey
            )->getString();
        }

        return Crypto::unseal(
            ciphertext: $encryptedString,
            privateKey: $recieverEncryptionPrivateKey
        )->getString();
    }

    /**
     * Sign string
     */
    public static function sign(
        string $string,
        SignatureSecretKey $authenticationSecretKey
    ): string {
        return Crypto::sign(
            message: $string,
            privateKey: $authenticationSecretKey
        );
    }

    /**
     * Verify string
     */
    public static function verify(
        string $string,
        string $signature,
        SignaturePublicKey $authenticationPublicKey
    ): bool {
        return Crypto::verify(
            message: $string,
            publicKey: $authenticationPublicKey,
            signature: $signature
        );
    }
}
