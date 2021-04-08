<?php

declare(strict_types=1);

namespace CQ\Crypto;

final class Random
{
    /**
     * Generate a more truly "random" alpha-numeric string.
     */
    public static function string(int $length = 32): string
    {
        return bin2hex(
            random_bytes(
                length: $length / 2
            )
        );
    }
}
