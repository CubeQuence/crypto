<?php

declare(strict_types=1);

namespace CQ\Crypto\Models;

use CQ\Crypto\Exceptions\AssymetricKeyException;
use CQ\Crypto\Providers\KeyProvider;
use ParagonIE\Halite\Asymmetric\EncryptionPublicKey;
use ParagonIE\Halite\Asymmetric\SignaturePublicKey;
use ParagonIE\Halite\EncryptionKeyPair;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\SignatureKeyPair;
use ParagonIE\HiddenString\HiddenString;

final class AsymmetricKey extends KeyProvider
{
    private SignatureKeyPair|SignaturePublicKey $authentication;
    private EncryptionKeyPair|EncryptionPublicKey $encryption;
    private bool $publicOnly = false;

    /**
     * Generate encryption keypair
     */
    protected function genKey(): void
    {
        $this->authentication = KeyFactory::generateSignatureKeyPair();
        $this->encryption = KeyFactory::generateEncryptionKeyPair();
    }

    /**
     * Import private or public key
     */
    protected function import(string $encodedKey): void
    {
        $decodedKey = json_decode(
            base64_decode($encodedKey)
        );

        $authenticationHiddenString = new HiddenString($decodedKey->authentication);
        $encryptionHiddenString = new HiddenString($decodedKey->encryption);


        if (!$decodedKey->public) {
            $this->authentication = KeyFactory::importSignatureKeyPair(
                keyData: $authenticationHiddenString
            );

            $this->encryption = KeyFactory::importEncryptionKeyPair(
                keyData: $encryptionHiddenString
            );

            return;
        }

        $this->authentication = KeyFactory::importSignaturePublicKey(
            keyData: $authenticationHiddenString
        );

        $this->encryption = KeyFactory::importEncryptionPublicKey(
            keyData: $encryptionHiddenString
        );

        $this->publicOnly = true;
    }

    /**
     * Export private key
     */
    public function export(): string
    {
        if ($this->publicOnly) {
            throw new AssymetricKeyException(
                message: "Can't export private keys of publicOnly AssymetricKey instance"
            );
        }

        $keypair = [
            'authentication' => KeyFactory::export(
                key:  $this->authentication
            )->getString(),
            'encryption' => KeyFactory::export(
                key:  $this->encryption
            )->getString(),
            'public' => false,
        ];

        return base64_encode(
            json_encode($keypair)
        );
    }

    /**
     * Export public key
     */
    public function exportPublic() : string
    {
        $keypair = [
            'authentication' => KeyFactory::export(
                key:  $this->authentication->getPublicKey()
            )->getString(),
            'encryption' => KeyFactory::export(
                key:  $this->encryption->getPublicKey()
            )->getString(),
            'public' => true,
        ];

        return base64_encode(
            json_encode($keypair)
        );
    }

    public function getPublicOnly() : bool
    {
        return $this->publicOnly;
    }

    public function getAuthentication(): SignatureKeyPair | SignaturePublicKey
    {
        return $this->authentication;
    }

    public function getEncryption(): EncryptionKeyPair | EncryptionPublicKey
    {
        return $this->encryption;
    }
}
