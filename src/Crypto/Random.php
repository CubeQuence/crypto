<?php

declare(strict_types=1);

namespace CQ\Crypto;

use CQ\Crypto\Exceptions\CryptoException;

final class Random
{
    public static function string(int $length = 32): string
    {
        try {
            return bin2hex(
                random_bytes(
                    length: $length / 2
                )
            );
        } catch (\Throwable $th) {
            throw new CryptoException(message: $th->getMessage());
        }
    }
}
