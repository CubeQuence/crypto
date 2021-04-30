<?php

declare(strict_types=1);

namespace CQ\Crypto;

use CQ\Crypto\Exceptions\TokenException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\Version2;

final class Token
{
    private static function getKey(string $key): SymmetricKey
    {
        $hashedKey = hash(
            algo: 'sha256',
            data: $key
        );

        $shortenedKey = substr($hashedKey, 0, 32);

        return new SymmetricKey(
            keyMaterial: $shortenedKey
        );
    }

    public static function create(string $key, array $data): string
    {
        return Version2::encrypt(
            data: json_encode($data),
            key: self::getKey(key: $key)
        );
    }

    public static function decode(string $key, string $givenToken): bool | object
    {
        try {
            $data = Version2::decrypt(
                data: $givenToken,
                key: self::getKey(key: $key)
            );
        } catch (PasetoException) {
            throw new TokenException();
        }

        return json_decode($data);
    }
}
