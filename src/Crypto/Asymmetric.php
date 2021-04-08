<?php

declare(strict_types=1);

namespace CQ\Crypto;

use CQ\Crypto\Models\AsymmetricKey;
use CQ\Crypto\Providers\CryptoProvider;
use ParagonIE\Halite\Asymmetric\Crypto;
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
        return Crypto::seal(
            plaintext: new HiddenString(value: $string),
            publicKey: $this->keypair->getEncryption()->getPublicKey()
        );
    }

    /**
     * Decrypt encryptedString
     */
    public function decrypt(string $encryptedString): string
    {
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
        return Crypto::verify(
            message: $string,
            publicKey: $this->keypair->getAuthentication()->getPublicKey(),
            signature: $signature
        );
    }
}
