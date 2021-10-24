<?php

declare(strict_types=1);

namespace CQ\Crypto\Models;

use CQ\Crypto\Providers\KeyProvider;
use CQ\Crypto\Random;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Keys\Version4\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\Version4\SymmetricKey as Version4SymmetricKey;

final class TokenKey extends KeyProvider
{
    private string $keystring;

    /**
     * Export key
     */
    public function export(): string
    {
        return base64_encode($this->keystring);
    }

    public function getAuthentication(): AsymmetricSecretKey
    {
        // AsymmetricSecretKey
        return KeyFactory::importAuthenticationKey(
            keyData: new HiddenString(value: $this->keystring)
        );
    }

    public function getEncryption(): Version4SymmetricKey
    {
        // Version4SymmetricKey
    }

    /**
     * Generate key
     */
    protected function genKey(): void
    {
        $randomString = Random::string(32); // TODO: maybe set longer length
        $hashedString = sha1($randomString);

        $this->keystring = substr($hashedString, 0, 32);
    }

    /**
     * Import key
     */
    protected function import(string $encodedKey): void
    {
        $this->keystring = base64_decode($encodedKey);
    }
}
