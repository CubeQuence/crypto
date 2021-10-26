<?php

declare(strict_types=1);

namespace CQ\Crypto\Models;

use CQ\Crypto\Random;
use CQ\Crypto\Exceptions\TokenException;
use ParagonIE\Paseto\Keys\Version4\SymmetricKey;

final class TokenKey
{
    private string $keystring;

    public function __construct(string | null $encodedKey = null)
    {
        if (!$encodedKey) {
            return $this->genKey();
        }

        $this->import(
            encodedKey: $encodedKey
        );
    }

    /**
     * Export key
     */
    public function export(): string
    {
        return base64_encode($this->keystring);
    }

    public function getAuthentication(): void
    {
        throw new TokenException('Authentication is not supported for TokenKey');
    }

    public function getEncryption(): SymmetricKey
    {
        return new SymmetricKey(
            keyMaterial: $this->keystring
        );
    }

    /**
     * Generate key
     */
    protected function genKey(): void
    {
        $this->keystring = Random::string(64);
    }

    /**
     * Import key
     */
    protected function import(string $encodedKey): void
    {
        $this->keystring = base64_decode($encodedKey);
    }
}
