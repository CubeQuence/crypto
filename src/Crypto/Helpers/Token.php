<?php

declare(strict_types=1);

namespace CQ\Crypto\Helpers;

use CQ\Crypto\Token as TokenProvider;

final class Token
{
    private static function getProvider(string $key = ''): TokenProvider
    {
        return new TokenProvider(key: $key);
    }

    public static function encrypt(string $key, array $data): string
    {
        return self::getProvider(key: $key)
            ->encrypt(data: $data);
    }

    public static function decrypt(string $key, string $token): object
    {
        return self::getProvider(key: $key)
            ->decrypt(token: $token);
    }

    public static function generateKey(): string
    {
        return self::getProvider()
            ->exportKey();
    }
}
