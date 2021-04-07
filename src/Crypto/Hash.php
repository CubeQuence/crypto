<?php

declare(strict_types=1);

namespace CQ\Crypto;

class Hash
{
    private static int $hash_cost = 2;

    /**
     * Hash string.
     */
    public static function make(string $string): string
    {
        if (! defined('PASSWORD_ARGON2ID')) {
            return password_hash(
                password: $string,
                algo: PASSWORD_BCRYPT
            );
        }

        $hash_options = [
            'memory_cost' => self::$hash_cost * PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost' => self::$hash_cost * PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads' => self::$hash_cost * PASSWORD_ARGON2_DEFAULT_THREADS,
        ];

        return password_hash(
            password: $string,
            algo: PASSWORD_ARGON2ID,
            options: $hash_options
        );
    }

    /**
     * Verify plain-text with hash.
     */
    public static function verify(
        string $string,
        string $hash
    ): bool {
        return password_verify(
            password: $string,
            hash: $hash
        );
    }
}
