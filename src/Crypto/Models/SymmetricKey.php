<?php

declare(strict_types=1);

namespace CQ\Crypto\Models;

use CQ\Crypto\Providers\KeyProvider;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\Symmetric\AuthenticationKey;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\HiddenString\HiddenString;

final class SymmetricKey extends KeyProvider
{
    private string $keystring;

    /**
     * Export key
     */
    public function export(): string
    {
        return base64_encode($this->keystring);
    }

    public function getAuthentication(): AuthenticationKey
    {
        return KeyFactory::importAuthenticationKey(
            keyData: new HiddenString(value: $this->keystring)
        );
    }

    public function getEncryption(): EncryptionKey
    {
        return KeyFactory::importEncryptionKey(
            keyData: new HiddenString(value: $this->keystring)
        );
    }

    /**
     * Generate key
     */
    protected function genKey(): void
    {
        $key = KeyFactory::generateEncryptionKey();

        $this->keystring = KeyFactory::export(key: $key)->getString();
    }

    /**
     * Import key
     */
    protected function import(string $encodedKey): void
    {
        $this->keystring = base64_decode($encodedKey);
    }
}
