<?php

declare(strict_types=1);

namespace CQ\Crypto\Providers;

use ParagonIE\Halite\Asymmetric\EncryptionPublicKey;
use ParagonIE\Halite\Asymmetric\SignaturePublicKey;
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
     * Generate key
     */
    abstract protected function genKey(): void;

    /**
     * Import key
     */
    abstract protected function import(string $encodedKey): void;

    /**
     * Export (private) key
     */
    abstract public function export(): string;

    abstract public function getAuthentication(): AuthenticationKey | SignatureKeyPair | SignaturePublicKey;

    abstract public function getEncryption(): EncryptionKey | EncryptionKeyPair | EncryptionPublicKey;
}
