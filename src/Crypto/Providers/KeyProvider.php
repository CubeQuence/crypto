<?php

declare(strict_types=1);

namespace CQ\Crypto\Providers;

use CQ\Crypto\Helpers\Keypair;
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

    abstract public function getAuthentication(): AuthenticationKey | Keypair;

    abstract public function getEncryption(): EncryptionKey | Keypair;

    /**
     * Generate key
     */
    abstract protected function genKey(): void;

    /**
     * Import key
     */
    abstract protected function import(string $encodedKey): void;
}
