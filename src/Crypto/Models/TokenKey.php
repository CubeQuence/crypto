<?php

declare(strict_types=1);

namespace CQ\Crypto\Models;

use CQ\Crypto\Random;
use CQ\Crypto\Exceptions\KeyException;
use CQ\Crypto\Providers\KeyProvider;
use ParagonIE\Paseto\Keys\Version4\SymmetricKey;

final class TokenKey extends KeyProvider
{
    private string $keystring;

    protected function generate(): void
    {
        $this->keystring = Random::string(64);
    }

    protected function import(string $encodedKey): void
    {
        $this->keystring = base64_decode($encodedKey);
    }

    public function export(): string
    {
        return base64_encode($this->keystring);
    }

    public function getAuthentication(): SymmetricKey
    {
        throw new KeyException('Authentication is not supported for TokenKey');
    }

    public function getEncryption(): SymmetricKey
    {
        return new SymmetricKey(
            keyMaterial: $this->keystring
        );
    }
}
