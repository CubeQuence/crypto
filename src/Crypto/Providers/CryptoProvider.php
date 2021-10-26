<?php

declare(strict_types=1);

namespace CQ\Crypto\Providers;

abstract class CryptoProvider
{
    /**
     * Optionally set key when creating instance
     */
    public function __construct(string $key = '')
    {
        $this->setKey(key: $key);
    }

    /**
     * Import base64 key
     */
    abstract public function setKey(string $key): void;

    /**
     * Export key in base64 format
     */
    abstract public function exportKey(): string;
}
