<?php

declare(strict_types=1);

namespace CQ\Crypto;

use CQ\Crypto\Models\AsymmetricKey;
use CQ\Crypto\Providers\CryptoProvider;
use ParagonIE\Halite\Asymmetric\Crypto;
use ParagonIE\HiddenString\HiddenString;

final class Asymmetric extends CryptoProvider
{
    private AsymmetricKey $key;

    public function __construct(string | null $key = null)
    {
        $this->setKey(key: $key);
    }

    public function setKey(string | null $key = null): void
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
        return Crypto::seal(
            plaintext: new HiddenString(value: $plaintext),
            publicKey: $this->key->getEncryption()->getPublicKey()
        );
    }

    public function decrypt(string $ciphertext): string
    {
        return Crypto::unseal(
            ciphertext: $ciphertext,
            privateKey: $this->key->getEncryption()->getSecretKey()
        )->getString();
    }

    public function sign(string $plaintext): string
    {
        return Crypto::sign(
            message: $plaintext,
            privateKey: $this->key->getAuthentication()->getSecretKey()
        );
    }

    public function verify(string $plaintext, string $signature): bool
    {
        return Crypto::verify(
            message: $plaintext,
            publicKey: $this->key->getAuthentication()->getPublicKey(),
            signature: $signature
        );
    }
}
