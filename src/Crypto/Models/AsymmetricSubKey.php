<?php

declare(strict_types=1);

namespace CQ\Crypto\Models;

use CQ\Crypto\Exceptions\KeyException;
use ParagonIE\Halite\Asymmetric\EncryptionPublicKey;
use ParagonIE\Halite\Asymmetric\EncryptionSecretKey;
use ParagonIE\Halite\Asymmetric\SignaturePublicKey;
use ParagonIE\Halite\Asymmetric\SignatureSecretKey;
use ParagonIE\Halite\KeyFactory;

final class AsymmetricSubKey
{
    public function __construct(
        private SignaturePublicKey | EncryptionPublicKey $publicKey,
        private SignatureSecretKey | EncryptionSecretKey | null $secretKey = null,
    ) {
    }

    public function getSecretKey(): SignatureSecretKey | EncryptionSecretKey
    {
        if (!$this->secretKey) {
            throw new KeyException(
                message: 'secretKey not set, this is a public key only instance'
            );
        }

        return $this->secretKey;
    }

    public function getPublicKey(): SignaturePublicKey | EncryptionPublicKey
    {
        return $this->publicKey;
    }

    public function exportSecretKey(): string
    {
        if (!$this->secretKey) {
            return null;
        }

        try {
            return KeyFactory::export(
                key: $this->secretKey
            )->getString();
        } catch (\Throwable $th) {
            throw new KeyException(message: $th->getMessage());
        }
    }

    public function exportPublicKey(): string
    {
        try {
            return KeyFactory::export(
                key: $this->publicKey
            )->getString();
        } catch (\Throwable $th) {
            throw new KeyException(message: $th->getMessage());
        }
    }
}
