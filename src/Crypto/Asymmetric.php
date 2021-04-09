<?php

declare(strict_types=1);

namespace CQ\Crypto;

use CQ\Crypto\Exceptions\AssymetricKeyException;
use CQ\Crypto\Models\AsymmetricKey;
use CQ\Crypto\Providers\CryptoProvider;
use ParagonIE\Halite\Asymmetric\Crypto;
use ParagonIE\Halite\Asymmetric\EncryptionPublicKey;
use ParagonIE\HiddenString\HiddenString;

final class Asymmetric extends CryptoProvider
{
    public function __construct(
        private AsymmetricKey $keypair
    ) {
    }

    /**
     * Encrypt string
     */
    public function encrypt(string $string): string
    {
        $publicKey = $this->keypair->getPublicOnly() ?
            $this->keypair->getEncryption()
            : $this->keypair->getEncryption()->getPublicKey();

        return Crypto::seal(
            plaintext: new HiddenString(value: $string),
            publicKey: $publicKey
        );
    }

    /**
     * Decrypt encryptedString
     */
    public function decrypt(string $encryptedString): string
    {
        if ($this->keypair->getEncryption() instanceof EncryptionPublicKey) {
            throw new AssymetricKeyException(
                message: "Can't decrypt with publicOnly AssymetricKey instance"
            );
        }

        return Crypto::unseal(
            ciphertext: $encryptedString,
            privateKey: $this->keypair->getEncryption()->getSecretKey()
        )->getString();
    }

    /**
     * Sign string
     */
    public function sign(string $string): string
    {
        if ($this->keypair->getAuthentication() instanceof EncryptionPublicKey) {
            throw new AssymetricKeyException(
                message: "Can't sign with publicOnly AssymetricKey instance"
            );
        }

        return Crypto::sign(
            message: $string,
            privateKey: $this->keypair->getAuthentication()->getSecretKey()
        );
    }

    /**
     * Verify string with signature
     */
    public function verify(
        string $string,
        string $signature
    ): bool {
        $publicKey = $this->keypair->getPublicOnly() ?
            $this->keypair->getAuthentication()
            : $this->keypair->getAuthentication()->getPublicKey();

        return Crypto::verify(
            message: $string,
            publicKey: $publicKey,
            signature: $signature
        );
    }
}
