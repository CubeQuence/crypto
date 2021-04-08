<?php

declare(strict_types=1);

namespace CQ\Crypto\Models;

use CQ\Crypto\Providers\KeyProvider;
use ParagonIE\Halite\EncryptionKeyPair;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\SignatureKeyPair;
use ParagonIE\HiddenString\HiddenString;

final class AsymmetricKey extends KeyProvider
{
    private SignatureKeyPair $authentication;
    private EncryptionKeyPair $encryption;

    /**
     * Generate encryption keypair
     */
    protected function genKey(): void
    {
        $this->authentication = KeyFactory::generateSignatureKeyPair();
        $this->encryption = KeyFactory::generateEncryptionKeyPair();
    }

    /**
     * Import keypair from string
     */
    protected function import(string $encodedKey): void
    {
        $decodedKey = json_decode(
            base64_decode($encodedKey)
        );

        $this->authentication = KeyFactory::importSignatureKeyPair(
            keyData: new HiddenString($decodedKey->authentication)
        );

        $this->encryption = KeyFactory::importEncryptionKeyPair(
            keyData: new HiddenString($decodedKey->encryption)
        );
    }

    /**
     * Turn keypair into string
     * to store in DB or file
     */
    public function export(): string
    {
        $keypair = [
            'authentication' => KeyFactory::export(
                key:  $this->authentication
            )->getString(),
            'encryption' => KeyFactory::export(
                key:  $this->encryption
            )->getString(),
        ];

        return base64_encode(
            json_encode($keypair)
        );
    }

    public function getAuthentication(): SignatureKeyPair
    {
        return $this->authentication;
    }

    public function getEncryption(): EncryptionKeyPair
    {
        return $this->encryption;
    }
}
