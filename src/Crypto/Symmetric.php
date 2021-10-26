<?php

declare(strict_types=1);

namespace CQ\Crypto;

use CQ\Crypto\Exceptions\CryptoException;
use CQ\Crypto\Models\SymmetricKey;
use CQ\Crypto\Providers\CryptoProvider;
use ParagonIE\Halite\Symmetric\Crypto;
use ParagonIE\HiddenString\HiddenString;

final class Symmetric extends CryptoProvider
{
    private SymmetricKey $key;

    public function setKey(string $key): void
    {
        $this->key = new SymmetricKey(encodedKey: $key);
    }

    public function exportKey(): string
    {
        return $this->key->export();
    }

    public function encrypt(string $plaintext): string
    {
        try {
            return Crypto::encrypt(
                plaintext: new HiddenString(value: $plaintext),
                secretKey: $this->key->getEncryption()
            );
        } catch (\Throwable $th) {
            throw new CryptoException(message: $th->getMessage());
        }
    }

    public function decrypt(string $ciphertext): string
    {
        try {
            return Crypto::decrypt(
                ciphertext: $ciphertext,
                secretKey: $this->key->getEncryption()
            )->getString();
        } catch (\Throwable $th) {
            throw new CryptoException(message: $th->getMessage());
        }
    }

    public function sign(string $plaintext): string
    {
        try {
            return Crypto::authenticate(
                message: $plaintext,
                secretKey: $this->key->getAuthentication()
            );
        } catch (\Throwable $th) {
            throw new CryptoException(message: $th->getMessage());
        }
    }

    public function verify(string $plaintext, string $signature): bool
    {
        try {
            return Crypto::verify(
                message: $plaintext,
                secretKey: $this->key->getAuthentication(),
                mac: $signature
            );
        } catch (\Throwable $th) {
            throw new CryptoException(message: $th->getMessage());
        }
    }
}
