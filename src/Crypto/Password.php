<?php

declare(strict_types=1);

namespace CQ\Crypto;

use CQ\Crypto\Models\SymmetricKey;

final class Password
{
    private Symmetric $symmetric;

    public function __construct(
        SymmetricKey $key
    ) {
        $this->symmetric = new Symmetric(key: $key);
    }

    /**
     * Hash and encrypt password
     */
    public function hash(string $plaintextPassword): string
    {
        $hashedPassword = Hash::make(
            string: $plaintextPassword
        );

        return $this->symmetric->encrypt(
            string: $hashedPassword
        );
    }

    /**
     * Verify password with encryptedHashedPassword
     */
    public function verify(
        string $plaintextPassword,
        string $encryptedHashedPassword
    ): bool {
        $hashedPassword = $this->symmetric->decrypt(
            encryptedString: $encryptedHashedPassword
        );

        return Hash::verify(
            string: $plaintextPassword,
            hash: $hashedPassword
        );
    }
}
