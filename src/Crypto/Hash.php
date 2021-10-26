<?php

declare(strict_types=1);

namespace CQ\Crypto;

use CQ\Crypto\Exceptions\CryptoException;

final class Hash
{
    public static function make(string $string): string
    {
        try {
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
        } catch (\Throwable $th) {
            throw new CryptoException(message: $th->getMessage());
        }
    }

    public static function verify(string $string, string $hash): bool
    {
        return password_verify(
            password: $string,
            hash: $hash
        );
    }
}
