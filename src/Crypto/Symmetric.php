<?php

declare(strict_types=1);

namespace CQ\Crypto;

use CQ\Crypto\Exceptions\KeyException;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\Symmetric\AuthenticationKey;
use ParagonIE\Halite\Symmetric\Crypto;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\HiddenString\HiddenString;

class Symmetric
{
    public function __construct(
        private string $keystring
    ) {
    }

    /**
     * Generate encryption key
     */
    public static function genKey(): string
    {
        $key = KeyFactory::generateEncryptionKey();
        $keystring = KeyFactory::export(key: $key)->getString();

        return $keystring;
    }

    /**
     * Create keyfactory for specified key type
     */
    public function getKey(string $keyType): EncryptionKey | AuthenticationKey
    {
        return match ($keyType) {
            'encryption' => KeyFactory::importEncryptionKey(
                keyData: new HiddenString(value: $this->keystring)
            ),
            'authentication' => KeyFactory::importAuthenticationKey(
                keyData: new HiddenString(value: $this->keystring)
            ),
            default => throw new KeyException('Invalid key type'),
        };
    }

    /**
     * Encrypt string
     */
    public function encrypt(string $string): string
    {
        $key = $this->getKey(
            keyType: 'encryption'
        );

        return Crypto::encrypt(
            plaintext: new HiddenString(value: $string),
            secretKey: $key
        );
    }

    /**
     * Decrypt string
     */
    public function decrypt(string $encryptedString): string
    {
        $key = $this->getKey(
            keyType: 'encryption'
        );

        return Crypto::decrypt(
            ciphertext: $encryptedString,
            secretKey: $key
        )->getString();
    }

    /**
     * Sign string
     */
    public function sign(string $string): string
    {
        $key = $this->getKey(
            keyType: 'authentication'
        );

        return Crypto::authenticate(
            message: $string,
            secretKey: $key
        );
    }

    /**
     * Verify string
     */
    public function verify(string $string, string $signature): bool
    {
        $key = $this->getKey(
            keyType: 'authentication'
        );

        return Crypto::verify(
            message: $string,
            secretKey: $key,
            mac: $signature
        );
    }
}
