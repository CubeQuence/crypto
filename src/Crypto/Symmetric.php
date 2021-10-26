<?php

declare(strict_types=1);

namespace CQ\Crypto;

use CQ\Crypto\Models\SymmetricKey;
use CQ\Crypto\Providers\CryptoProvider;
use ParagonIE\Halite\Symmetric\Crypto;
use ParagonIE\HiddenString\HiddenString;

final class Symmetric extends CryptoProvider
{
    private SymmetricKey $key;

    public function setKey(string | null $key = null): void
    {
        $this->key = new SymmetricKey(encodedKey: $key);
    }

    public function exportKey(): string
    {
        return $this->key->export();
    }

    public function encrypt(string $plaintext): string
    {
        return Crypto::encrypt(
            plaintext: new HiddenString(value: $plaintext),
            secretKey: $this->key->getEncryption()
        );
    }

    public function decrypt(string $ciphertext): string
    {
        return Crypto::decrypt(
            ciphertext: $ciphertext,
            secretKey: $this->key->getEncryption()
        )->getString();
    }

    public function sign(string $plaintext): string
    {
        return Crypto::authenticate(
            message: $plaintext,
            secretKey: $this->key->getAuthentication()
        );
    }

    public function verify(string $plaintext, string $signature): bool
    {
        return Crypto::verify(
            message: $plaintext,
            secretKey: $this->key->getAuthentication(),
            mac: $signature
        );
    }
}
