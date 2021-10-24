<?php

declare(strict_types=1);

namespace CQ\Crypto;

final class Hash
{
    /**
     * Hash string.
     */
    public static function make(string $string): string
    {
        if (defined('PASSWORD_ARGON2ID')) {
            return password_hash(
                password: $string,
                algo: PASSWORD_ARGON2ID
            );
        }

        return password_hash(
            password: $string,
            algo: PASSWORD_BCRYPT
        );
    }

    /**
     * Verify plain-text with hash.
     */
    public static function verify(string $string, string $hash): bool
    {
        return password_verify(
            password: $string,
            hash: $hash
        );
    }
}
