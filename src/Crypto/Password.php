<?php

declare(strict_types=1);

namespace CQ\Crypto;

final class Password
{
    private Symmetric $symmetric;

    public function __construct(string | null $key = null)
    {
        $this->symmetric = new Symmetric(
            key: $key
        );
    }

    public function setKey(string | null $key = null): void
    {
        $this->symmetric->setKey(key: $key);
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
        $hash = Hash::make(string: $plaintext);

        return $this->symmetric->encrypt(plaintext: $hash);
    }

    /**
     * Verify password with encryptedHashed
     */
    public function verify(
        string $plaintext,
        string $encryptedHash
    ): bool {
        $hash = $this->symmetric->decrypt(
            ciphertext: $encryptedHash
        );

        return Hash::verify(string: $plaintext, hash: $hash);
    }
}
