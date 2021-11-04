<?php

declare(strict_types=1);

namespace CQ\Crypto\Helpers;

use CQ\Crypto\Symmetric as SymmetricProvider;

final class Symmetric
{
    private static function getProvider(string $key = ''): SymmetricProvider
    {
        return new SymmetricProvider(key: $key);
    }

    public static function encrypt(string $key, string $plaintext): string
    {
        return self::getProvider(key: $key)
            ->encrypt(plaintext: $plaintext);
    }

    public static function decrypt(string $key, string $ciphertext): string
    {
        return self::getProvider(key: $key)
            ->decrypt(ciphertext: $ciphertext);
    }

    public static function sign(string $key, string $plaintext): string
    {
        return self::getProvider(key: $key)
            ->sign(plaintext: $plaintext);
    }

    public static function verify(string $key, string $plaintext, string $signature): bool
    {
        return self::getProvider(key: $key)
            ->verify(plaintext: $plaintext, signature: $signature);
    }

    public static function generateKey(): string
    {
        return self::getProvider()
            ->exportKey();
    }
}
