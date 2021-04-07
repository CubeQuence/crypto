<?php

declare(strict_types=1);

use CQ\Crypto\Asymmetric;
use CQ\Crypto\Models\Keypair;

try {
    $string = 'Hello World!';

    $assymetricKeypair = Asymmetric::genKey();
    $encodedKeypair = $assymetricKeypair->toString();

    $newAssymetricKeypair = new Keypair();
    $newAssymetricKeypair->loadFromString(
        encodedKeypair: $encodedKeypair
    );

    $assymetricEncryptedString = Asymmetric::encrypt(
        string: $string,
        recieverEncryptionPublicKey: $assymetricKeypair->getEncryption()->getPublicKey()
    );
    $assymetricDecryptedString = Asymmetric::decrypt(
        encryptedString: $assymetricEncryptedString,
        recieverEncryptionPrivateKey: $newAssymetricKeypair->getEncryption()->getSecretKey()
    );
    $assymetricSignature = Asymmetric::sign(
        string: $string,
        authenticationSecretKey: $assymetricKeypair->getAuthentication()->getSecretKey()
    );
    $assymetricVerify = Asymmetric::verify(
        string: $string,
        signature: $assymetricSignature,
        authenticationPublicKey: $newAssymetricKeypair->getAuthentication()->getPublicKey()
    );
} catch (\Throwable $th) {
    echo $th->getMessage();
    exit;
}

echo json_encode([
    'string' => $string,
    'assymetric' => [
        'keypair' => $encodedKeypair,
        'encrypted' => $assymetricEncryptedString,
        'decrypted' => $assymetricDecryptedString,
        'signature' => $assymetricSignature,
        'verify' => $assymetricVerify,
    ],
]);
