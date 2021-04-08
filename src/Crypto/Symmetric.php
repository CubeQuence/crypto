<?php

declare(strict_types=1);

namespace CQ\Crypto;

use CQ\Crypto\Models\SymmetricKey;
use CQ\Crypto\Providers\CryptoProvider;
use ParagonIE\Halite\Symmetric\Crypto;
use ParagonIE\HiddenString\HiddenString;

final class Symmetric extends CryptoProvider
{
    public function __construct(
        private SymmetricKey $key
    ) {
    }

    /**
     * Encrypt string
     */
    public function encrypt(string $string): string
    {
        return Crypto::encrypt(
            plaintext: new HiddenString(value: $string),
            secretKey: $this->key->getEncryption()
        );
    }

    /**
     * Decrypt encryptedString
     */
    public function decrypt(string $encryptedString): string
    {
        return Crypto::decrypt(
            ciphertext: $encryptedString,
            secretKey: $this->key->getEncryption()
        )->getString();
    }

    /**
     * Sign string
     */
    public function sign(string $string): string
    {
        return Crypto::authenticate(
            message: $string,
            secretKey: $this->key->getAuthentication()
        );
    }

    /**
     * Verify string with signature
     */
    public function verify(string $string, string $signature): bool
    {
        return Crypto::verify(
            message: $string,
            secretKey: $this->key->getAuthentication(),
            mac: $signature
        );
    }
}
