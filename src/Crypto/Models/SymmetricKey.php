<?php

declare(strict_types=1);

namespace CQ\Crypto\Models;

use CQ\Crypto\Exceptions\KeyException;
use CQ\Crypto\Providers\KeyProvider;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\Symmetric\AuthenticationKey;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\HiddenString\HiddenString;

final class SymmetricKey extends KeyProvider
{
    private string $keystring;

    protected function generate(): void
    {
        try {
            $key = KeyFactory::generateEncryptionKey();

            $this->keystring = KeyFactory::export(key: $key)->getString();
        } catch (\Throwable $th) {
            throw new KeyException(message: $th->getMessage());
        }
    }

    protected function import(string $encodedKey): void
    {
        $this->keystring = base64_decode($encodedKey);
    }

    public function export(): string
    {
        return base64_encode($this->keystring);
    }

    public function getAuthentication(): AuthenticationKey
    {
        try {
            return KeyFactory::importAuthenticationKey(
                keyData: new HiddenString(value: $this->keystring)
            );
        } catch (\Throwable $th) {
            throw new KeyException(message: $th->getMessage());
        }
    }

    public function getEncryption(): EncryptionKey
    {
        try {
            return KeyFactory::importEncryptionKey(
                keyData: new HiddenString(value: $this->keystring)
            );
        } catch (\Throwable $th) {
            throw new KeyException(message: $th->getMessage());
        }
    }
}
