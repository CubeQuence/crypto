<?php

declare(strict_types=1);

namespace CQ\Crypto\Models;

use CQ\Crypto\Providers\KeyProvider;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\HiddenString\HiddenString;

final class AsymmetricKey extends KeyProvider
{
    private AsymmetricSubKey $authentication;
    private AsymmetricSubKey $encryption;

    /**
     * Export private key
     */
    public function export(): string
    {
        $keypair = [
            'authentication' => [
                'publicKey' => $this->authentication->exportPublicKey(),
                'secretKey' => $this->authentication->exportSecretKey(),
            ],
            'encryption' => [
                'publicKey' => $this->encryption->exportPublicKey(),
                'secretKey' => $this->encryption->exportSecretKey(),
            ],
        ];

        return base64_encode(
            json_encode($keypair)
        );
    }

    /**
     * Export public key
     */
    public function exportPublic(): string
    {
        $keypair = [
            'authentication' => [
                'publicKey' => $this->authentication->exportPublicKey(),
                'secretKey' => null,
            ],
            'encryption' => [
                'publicKey' => $this->encryption->exportPublicKey(),
                'secretKey' => null,
            ],
        ];

        return base64_encode(
            json_encode($keypair)
        );
    }

    public function getAuthentication(): AsymmetricSubKey
    {
        return $this->authentication;
    }

    public function getEncryption(): AsymmetricSubKey
    {
        return $this->encryption;
    }

    /**
     * Generate encryption keypair
     */
    protected function genKey(): void
    {
        $authenticationKeypair = KeyFactory::generateSignatureKeyPair();
        $encryptionKeypair = KeyFactory::generateEncryptionKeypair();

        $this->authentication = new AsymmetricSubKey(
            publicKey: $authenticationKeypair->getPublicKey(),
            secretKey: $authenticationKeypair->getSecretKey()
        );

        $this->encryption = new AsymmetricSubKey(
            publicKey: $encryptionKeypair->getPublicKey(),
            secretKey: $encryptionKeypair->getSecretKey()
        );
    }

    /**
     * Import private or public key
     */
    protected function import(string $encodedKey): void
    {
        $decodedKey = json_decode(
            base64_decode($encodedKey)
        );

        $this->authentication = new AsymmetricSubKey(
            publicKey: KeyFactory::importSignaturePublicKey(
                keyData: new HiddenString(
                    value: $decodedKey->authentication->publicKey
                )
            ),
            secretKey: $decodedKey->authentication->secretKey ?
                KeyFactory::importSignatureSecretKey(
                    keyData: new HiddenString(
                        value: $decodedKey->authentication->secretKey
                    )
                ) : null // If secretKey isset import it otherwise set null
        );

        $this->encryption = new AsymmetricSubKey(
            publicKey: KeyFactory::importEncryptionPublicKey(
                keyData: new HiddenString(
                    value: $decodedKey->encryption->publicKey
                )
            ),
            secretKey: $decodedKey->encryption->secretKey ?
                KeyFactory::importEncryptionSecretKey(
                    keyData: new HiddenString(
                        value: $decodedKey->encryption->secretKey
                    )
                ) : null // If secretKey isset import it otherwise set null
        );
    }
}
