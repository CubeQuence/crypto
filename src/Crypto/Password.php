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
    public function hash(
        string $plaintextPassword,
        ?string $context = null
    ): string {
        $plaintextPasswordWithContext = $plaintextPassword . $context;

        $hashedPassword = Hash::make(
            string: $plaintextPasswordWithContext
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
        string $encryptedHashedPassword,
        ?string $context = null,
    ): bool {
        $plaintextPasswordWithContext = $plaintextPassword . $context;

        $hashedPassword = $this->symmetric->decrypt(
            encryptedString: $encryptedHashedPassword
        );

        return Hash::verify(
            string: $plaintextPasswordWithContext,
            hash: $hashedPassword
        );
    }
}
