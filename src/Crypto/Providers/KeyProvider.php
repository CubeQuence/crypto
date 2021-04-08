<?php

declare(strict_types=1);

namespace CQ\Crypto\Providers;

use ParagonIE\Halite\Symmetric\AuthenticationKey;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\Halite\SignatureKeyPair;
use ParagonIE\Halite\EncryptionKeyPair;

abstract class KeyProvider
{
    public function __construct(string | null $encodedKey = null)
    {
        if (! $encodedKey) {
            return $this->genKey();
        }

        $this->import(
            encodedKey: $encodedKey
        );
    }

    /**
     * Turn key into string
     * to store in DB or file
     */
    abstract public function export(): string;

    abstract public function getAuthentication(): AuthenticationKey | SignatureKeyPair;

    abstract public function getEncryption(): EncryptionKey | EncryptionKeyPair;

    /**
     * Generate encryption key
     */
    abstract protected function genKey(): void;

    /**
     * Import key from string
     */
    abstract protected function import(string $encodedKey): void;
}
