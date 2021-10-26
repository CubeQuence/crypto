<?php

declare(strict_types=1);

namespace CQ\Crypto\Providers;

use CQ\Crypto\Models\AsymmetricSubKey;
use ParagonIE\Halite\Symmetric\AuthenticationKey;
use ParagonIE\Halite\Symmetric\EncryptionKey;

abstract class KeyProvider
{
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
     * Export (private) key
     */
    abstract public function export(): string;

    abstract public function getAuthentication(): AuthenticationKey | AsymmetricSubKey;

    abstract public function getEncryption(): EncryptionKey | AsymmetricSubKey;

    /**
     * Generate key
     */
    abstract protected function genKey(): void;

    /**
     * Import key
     */
    abstract protected function import(string $encodedKey): void;
}
