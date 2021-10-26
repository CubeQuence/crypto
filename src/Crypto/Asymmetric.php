<?php

declare(strict_types=1);

namespace CQ\Crypto;

use CQ\Crypto\Exceptions\CryptoException;
use CQ\Crypto\Models\AsymmetricKey;
use CQ\Crypto\Providers\CryptoProvider;
use ParagonIE\Halite\Asymmetric\Crypto;
use ParagonIE\HiddenString\HiddenString;

final class Asymmetric extends CryptoProvider
{
    private AsymmetricKey $key;

    public function setKey(string $key): void
    {
        $this->key = new AsymmetricKey(encodedKey: $key);
    }

    public function exportKey(): string
    {
        return $this->key->export();
    }

    public function exportPublicKey(): string
    {
        return $this->key->exportPublic();
    }

    public function encrypt(string $plaintext): string
    {
        try {
            return Crypto::seal(
                plaintext: new HiddenString(value: $plaintext),
                publicKey: $this->key->getEncryption()->getPublicKey()
            );
        } catch (\Throwable $th) {
            throw new CryptoException(message: $th->getMessage());
        }
    }

    public function decrypt(string $ciphertext): string
    {
        try {
            return Crypto::unseal(
                ciphertext: $ciphertext,
                privateKey: $this->key->getEncryption()->getSecretKey()
            )->getString();
        } catch (\Throwable $th) {
            throw new CryptoException(message: $th->getMessage());
        }
    }

    public function sign(string $plaintext): string
    {
        try {
            return Crypto::sign(
                message: $plaintext,
                privateKey: $this->key->getAuthentication()->getSecretKey()
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
                publicKey: $this->key->getAuthentication()->getPublicKey(),
                signature: $signature
            );
        } catch (\Throwable $th) {
            throw new CryptoException(message: $th->getMessage());
        }
    }
}
