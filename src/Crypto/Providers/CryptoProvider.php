<?php

declare(strict_types=1);

namespace CQ\Crypto\Providers;

abstract class CryptoProvider
{
    /**
     * Encrypt string
     */
    abstract public function encrypt(string $plaintext): string;

    /**
     * Decrypt encryptedString
     */
    abstract public function decrypt(string $ciphertext): string;

    /**
     * Sign string
     */
    abstract public function sign(string $plaintext): string;

    /**
     * Verify string with signature
     */
    abstract public function verify(string $plaintext, string $signature): bool;
}
