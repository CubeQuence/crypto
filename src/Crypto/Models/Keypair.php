<?php

declare(strict_types=1);

namespace CQ\Crypto\Models;

use ParagonIE\Halite\Asymmetric\EncryptionSecretKey;
use ParagonIE\Halite\Asymmetric\SignatureSecretKey;
use ParagonIE\Halite\SignatureKeyPair;
use ParagonIE\Halite\EncryptionKeyPair;
use ParagonIE\HiddenString\HiddenString;

final class Keypair
{
    private SignatureKeyPair $authentication;
    private EncryptionKeyPair $encryption;

    public function setAuthentication(SignatureKeyPair $authentication) : void
    {
        $this->authentication = $authentication;
    }

    public function getAuthentication() : SignatureKeyPair
    {
        return $this->authentication;
    }

    public function setEncryption(EncryptionKeyPair $encryption) : void
    {
        $this->encryption = $encryption;
    }

    public function getEncryption() : EncryptionKeyPair
    {
        return $this->encryption;
    }

    /**
     * Turn keypair into string
     * to store in DB or file
     */
    public function toString() : string
    {
        $keypair = [
            'authentication' => sodium_bin2hex(
                $this->authentication->getSecretKey()->getRawKeyMaterial()
            ),
            'encryption' => sodium_bin2hex(
                $this->encryption->getSecretKey()->getRawKeyMaterial()
            ),
        ];

        $encodedKeypair = base64_encode(
            json_encode($keypair)
        );

        return $encodedKeypair;
    }

    /**
     * Convert string to keypair
     */
    public function loadFromString(string $encodedKeypair) : void
    {
        $decodedKeypair = json_decode(
            base64_decode($encodedKeypair)
        );

        $authentication =  new SignatureSecretKey(
            new HiddenString(sodium_hex2bin($decodedKeypair->authentication))
        );

        $encryption =  new EncryptionSecretKey(
            new HiddenString(sodium_hex2bin($decodedKeypair->encryption))
        );

        $this->setAuthentication(
            new SignatureKeyPair($authentication)
        );

        $this->setEncryption(
            new EncryptionKeyPair($encryption)
        );
    }
}
