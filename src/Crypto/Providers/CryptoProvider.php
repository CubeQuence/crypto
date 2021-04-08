<?php

declare(strict_types=1);

namespace CQ\Crypto\Providers;

abstract class CryptoProvider
{
    /**
     * Encrypt string
     */
    abstract public function encrypt(string $string): string;

    /**
     * Decrypt encryptedString
     */
    abstract public function decrypt(string $encryptedString): string;

    /**
     * Sign string
     */
    abstract public function sign(string $string): string;

    /**
     * Verify string with signature
     */
    abstract public function verify(string $string, string $signature): bool;
}
