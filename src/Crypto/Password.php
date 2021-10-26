<?php

declare(strict_types=1);

namespace CQ\Crypto;

use CQ\Crypto\Exceptions\CryptoException;
use CQ\Crypto\Providers\CryptoProvider;

final class Password extends CryptoProvider
{
    private Symmetric $symmetric;

    public function setKey(string $key): void
    {
        $this->symmetric = new Symmetric(
            key: $key
        );
    }

    public function exportKey(): string
    {
        return $this->symmetric->exportKey();
    }

    /**
     * Hash and encrypt string
     */
    public function hash(string $plaintext): string
    {
        try {
            $hash = Hash::make(string: $plaintext);

            return $this->symmetric->encrypt(plaintext: $hash);
        } catch (\Throwable $th) {
            throw new CryptoException(message: $th->getMessage());
        }
    }

    /**
     * Verify password with encryptedHashed
     */
    public function verify(string $plaintext, string $encryptedHash): bool
    {
        try {
            $hash = $this->symmetric->decrypt(
                ciphertext: $encryptedHash
            );

            return Hash::verify(string: $plaintext, hash: $hash);
        } catch (\Throwable $th) {
            throw new CryptoException(message: $th->getMessage());
        }
    }
}
