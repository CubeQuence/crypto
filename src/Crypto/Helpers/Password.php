<?php

declare(strict_types=1);

namespace CQ\Crypto\Helpers;

use CQ\Crypto\Password as PasswordProvider;

final class Password
{
    private static function getProvider(string $key = ''): PasswordProvider
    {
        return new PasswordProvider(key: $key);
    }

    public static function hash(string $key, string $plaintext): string
    {
        return self::getProvider(key: $key)
            ->hash(plaintext: $plaintext);
    }

    public static function verify(string $key, string $plaintext, string $encryptedHash): bool
    {
        return self::getProvider(key: $key)
            ->verify(
                plaintext: $plaintext,
                encryptedHash: $encryptedHash
            );
    }

    public static function generateKey(): string
    {
        return self::getProvider()
            ->exportKey();
    }
}
