<?php

declare(strict_types=1);

namespace CQ\Crypto;

class Password
{
    private Symmetric $symmetric;

    public function __construct(
        string $keystring
    ) {
        $this->symmetric = new Symmetric(
            keystring: $keystring
        );
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
     * Verify password
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
            check_against: $plaintextPasswordWithContext,
            hash: $hashedPassword
        );
    }
}
