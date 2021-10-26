<?php

declare(strict_types=1);

namespace CQ\Crypto\Providers;

use CQ\Crypto\Models\AsymmetricSubKey;
use ParagonIE\Halite\Symmetric\AuthenticationKey;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\Paseto\Keys\Version4\SymmetricKey;

abstract class KeyProvider
{
    public function __construct(string $encodedKey = '')
    {
        if (!$encodedKey) {
            return $this->generate();
        }

        $this->import(encodedKey: $encodedKey);
    }

    /**
     * Generate key
     */
    abstract protected function generate(): void;

    /**
     * Import key
     */
    abstract protected function import(string $encodedKey): void;

    /**
     * Export (private) key
     */
    abstract public function export(): string;

    /**
     * Get signing and verifying part of key
     */
    abstract public function getAuthentication(): AuthenticationKey | AsymmetricSubKey | SymmetricKey;

    /**
     * Get encryption and decryption part of key
     */
    abstract public function getEncryption(): EncryptionKey | AsymmetricSubKey | SymmetricKey;
}
