<?php

declare(strict_types=1);

use CQ\Crypto\Asymmetric;
use CQ\Crypto\Models\AsymmetricKey;

try {
    $string = 'Hello World!';

    // If no encodedKey is provided a new one is generated
    $keypair = new AsymmetricKey();
    $exportKeypair = $keypair->export();

    // By providing an exported key you can import it
    $keypair2 = new AsymmetricKey(encodedKey: $exportKeypair);
    $exportKeypair2 = $keypair2->export();

    $client = new Asymmetric(
        keypair: $keypair
    );
    $client2 = new Asymmetric(
        keypair: $keypair2
    );

    $encryptedString = $client->encrypt(
        string: $string
    );
    $decryptedString = $client2->decrypt(
        encryptedString: $encryptedString
    );

    $signature = $client->sign(
        string: $string
    );
    $verify = $client2->verify(
        string: $string,
        signature: $signature
    );
} catch (\Throwable $error) {
    echo $error->getMessage();
    exit;
}

echo json_encode([
    'string' => $string,
    'export' => $exportKey,
    'export2' => $exportKey2,
    'encrypted' => $encryptedString,
    'decrypted' => $decryptedString,
    'signature' => $signature,
    'verify' => $verify,
]);
