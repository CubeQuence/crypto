<?php

declare(strict_types=1);

namespace CQ\Crypto;

use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\Version2;

final class Token
{
    public static function create(string $key, array $data): string
    {
        return Version2::encrypt(
            data: json_encode($data),
            key: new SymmetricKey(
                keyMaterial: $key
            )
        );
    }

    public static function decode(string $key, string $givenToken): bool | object
    {
        try {
            $decryptedToken = Version2::decrypt(
                data: $givenToken,
                key: new SymmetricKey(
                    keyMaterial: $key
                )
            );
        } catch (PasetoException) {
            return false;
        }

        return json_decode($decryptedToken);
    }
}
